// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/devlink.yaml */
/* YNL-GEN user source */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#include <stdlib.h>
#include <string.h>
#include "devlink-user.h"
#include "ynl.h"
#include <linux/devlink.h>

#include <linux/genetlink.h>

/* Enums */
static const char * const devlink_op_strmap[] = {
	[3] = "get",
	// skip "port-get", duplicate reply value
	[DEVLINK_CMD_PORT_NEW] = "port-new",
	[13] = "sb-get",
	[17] = "sb-pool-get",
	[21] = "sb-port-pool-get",
	[25] = "sb-tc-pool-bind-get",
	[DEVLINK_CMD_ESWITCH_GET] = "eswitch-get",
	[DEVLINK_CMD_DPIPE_TABLE_GET] = "dpipe-table-get",
	[DEVLINK_CMD_DPIPE_ENTRIES_GET] = "dpipe-entries-get",
	[DEVLINK_CMD_DPIPE_HEADERS_GET] = "dpipe-headers-get",
	[DEVLINK_CMD_RESOURCE_DUMP] = "resource-dump",
	[DEVLINK_CMD_RELOAD] = "reload",
	[DEVLINK_CMD_PARAM_GET] = "param-get",
	[DEVLINK_CMD_REGION_GET] = "region-get",
	[DEVLINK_CMD_REGION_NEW] = "region-new",
	[DEVLINK_CMD_REGION_READ] = "region-read",
	[DEVLINK_CMD_PORT_PARAM_GET] = "port-param-get",
	[DEVLINK_CMD_INFO_GET] = "info-get",
	[DEVLINK_CMD_HEALTH_REPORTER_GET] = "health-reporter-get",
	[DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET] = "health-reporter-dump-get",
	[63] = "trap-get",
	[67] = "trap-group-get",
	[71] = "trap-policer-get",
	[76] = "rate-get",
	[80] = "linecard-get",
	[DEVLINK_CMD_SELFTESTS_GET] = "selftests-get",
};

const char *devlink_op_str(int op)
{
	if (op < 0 || op >= (int)YNL_ARRAY_SIZE(devlink_op_strmap))
		return NULL;
	return devlink_op_strmap[op];
}

static const char * const devlink_sb_pool_type_strmap[] = {
	[0] = "ingress",
	[1] = "egress",
};

const char *devlink_sb_pool_type_str(enum devlink_sb_pool_type value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_sb_pool_type_strmap))
		return NULL;
	return devlink_sb_pool_type_strmap[value];
}

static const char * const devlink_port_type_strmap[] = {
	[0] = "notset",
	[1] = "auto",
	[2] = "eth",
	[3] = "ib",
};

const char *devlink_port_type_str(enum devlink_port_type value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_port_type_strmap))
		return NULL;
	return devlink_port_type_strmap[value];
}

static const char * const devlink_port_flavour_strmap[] = {
	[0] = "physical",
	[1] = "cpu",
	[2] = "dsa",
	[3] = "pci-pf",
	[4] = "pci-vf",
	[5] = "virtual",
	[6] = "unused",
	[7] = "pci-sf",
};

const char *devlink_port_flavour_str(enum devlink_port_flavour value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_port_flavour_strmap))
		return NULL;
	return devlink_port_flavour_strmap[value];
}

static const char * const devlink_port_fn_state_strmap[] = {
	[0] = "inactive",
	[1] = "active",
};

const char *devlink_port_fn_state_str(enum devlink_port_fn_state value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_port_fn_state_strmap))
		return NULL;
	return devlink_port_fn_state_strmap[value];
}

static const char * const devlink_port_fn_opstate_strmap[] = {
	[0] = "detached",
	[1] = "attached",
};

const char *devlink_port_fn_opstate_str(enum devlink_port_fn_opstate value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_port_fn_opstate_strmap))
		return NULL;
	return devlink_port_fn_opstate_strmap[value];
}

static const char * const devlink_port_fn_attr_cap_strmap[] = {
	[0] = "roce-bit",
	[1] = "migratable-bit",
	[2] = "ipsec-crypto-bit",
	[3] = "ipsec-packet-bit",
};

const char *devlink_port_fn_attr_cap_str(enum devlink_port_fn_attr_cap value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_port_fn_attr_cap_strmap))
		return NULL;
	return devlink_port_fn_attr_cap_strmap[value];
}

static const char * const devlink_rate_type_strmap[] = {
	[0] = "leaf",
	[1] = "node",
};

const char *devlink_rate_type_str(enum devlink_rate_type value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_rate_type_strmap))
		return NULL;
	return devlink_rate_type_strmap[value];
}

static const char * const devlink_sb_threshold_type_strmap[] = {
	[0] = "static",
	[1] = "dynamic",
};

const char *devlink_sb_threshold_type_str(enum devlink_sb_threshold_type value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_sb_threshold_type_strmap))
		return NULL;
	return devlink_sb_threshold_type_strmap[value];
}

static const char * const devlink_eswitch_mode_strmap[] = {
	[0] = "legacy",
	[1] = "switchdev",
	[2] = "switchdev-inactive",
};

const char *devlink_eswitch_mode_str(enum devlink_eswitch_mode value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_eswitch_mode_strmap))
		return NULL;
	return devlink_eswitch_mode_strmap[value];
}

static const char * const devlink_eswitch_inline_mode_strmap[] = {
	[0] = "none",
	[1] = "link",
	[2] = "network",
	[3] = "transport",
};

const char *
devlink_eswitch_inline_mode_str(enum devlink_eswitch_inline_mode value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_eswitch_inline_mode_strmap))
		return NULL;
	return devlink_eswitch_inline_mode_strmap[value];
}

static const char * const devlink_eswitch_encap_mode_strmap[] = {
	[0] = "none",
	[1] = "basic",
};

const char *
devlink_eswitch_encap_mode_str(enum devlink_eswitch_encap_mode value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_eswitch_encap_mode_strmap))
		return NULL;
	return devlink_eswitch_encap_mode_strmap[value];
}

static const char * const devlink_dpipe_header_id_strmap[] = {
	[0] = "ethernet",
	[1] = "ipv4",
	[2] = "ipv6",
};

const char *devlink_dpipe_header_id_str(enum devlink_dpipe_header_id value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_dpipe_header_id_strmap))
		return NULL;
	return devlink_dpipe_header_id_strmap[value];
}

static const char * const devlink_dpipe_match_type_strmap[] = {
	[0] = "field-exact",
};

const char *devlink_dpipe_match_type_str(enum devlink_dpipe_match_type value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_dpipe_match_type_strmap))
		return NULL;
	return devlink_dpipe_match_type_strmap[value];
}

static const char * const devlink_dpipe_action_type_strmap[] = {
	[0] = "field-modify",
};

const char *devlink_dpipe_action_type_str(enum devlink_dpipe_action_type value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_dpipe_action_type_strmap))
		return NULL;
	return devlink_dpipe_action_type_strmap[value];
}

static const char * const devlink_dpipe_field_mapping_type_strmap[] = {
	[0] = "none",
	[1] = "ifindex",
};

const char *
devlink_dpipe_field_mapping_type_str(enum devlink_dpipe_field_mapping_type value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_dpipe_field_mapping_type_strmap))
		return NULL;
	return devlink_dpipe_field_mapping_type_strmap[value];
}

static const char * const devlink_resource_unit_strmap[] = {
	[0] = "entry",
};

const char *devlink_resource_unit_str(enum devlink_resource_unit value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_resource_unit_strmap))
		return NULL;
	return devlink_resource_unit_strmap[value];
}

static const char * const devlink_reload_action_strmap[] = {
	[1] = "driver-reinit",
	[2] = "fw-activate",
};

const char *devlink_reload_action_str(enum devlink_reload_action value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_reload_action_strmap))
		return NULL;
	return devlink_reload_action_strmap[value];
}

static const char * const devlink_param_cmode_strmap[] = {
	[0] = "runtime",
	[1] = "driverinit",
	[2] = "permanent",
};

const char *devlink_param_cmode_str(enum devlink_param_cmode value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_param_cmode_strmap))
		return NULL;
	return devlink_param_cmode_strmap[value];
}

static const char * const devlink_flash_overwrite_strmap[] = {
	[0] = "settings-bit",
	[1] = "identifiers-bit",
};

const char *devlink_flash_overwrite_str(enum devlink_flash_overwrite value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_flash_overwrite_strmap))
		return NULL;
	return devlink_flash_overwrite_strmap[value];
}

static const char * const devlink_trap_action_strmap[] = {
	[0] = "drop",
	[1] = "trap",
	[2] = "mirror",
};

const char *devlink_trap_action_str(enum devlink_trap_action value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_trap_action_strmap))
		return NULL;
	return devlink_trap_action_strmap[value];
}

static const char * const devlink_trap_type_strmap[] = {
	[0] = "drop",
	[1] = "exception",
	[2] = "control",
};

const char *devlink_trap_type_str(enum devlink_trap_type value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_trap_type_strmap))
		return NULL;
	return devlink_trap_type_strmap[value];
}

static const char * const devlink_var_attr_type_strmap[] = {
	[1] = "u8",
	[2] = "u16",
	[3] = "u32",
	[4] = "u64",
	[5] = "string",
	[6] = "flag",
	[10] = "nul-string",
	[11] = "binary",
};

const char *devlink_var_attr_type_str(enum devlink_var_attr_type value)
{
	if (value < 0 || value >= (int)YNL_ARRAY_SIZE(devlink_var_attr_type_strmap))
		return NULL;
	return devlink_var_attr_type_strmap[value];
}

/* Policies */
const struct ynl_policy_attr devlink_dl_dpipe_match_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_DPIPE_MATCH_TYPE] = { .name = "dpipe-match-type", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_DPIPE_HEADER_ID] = { .name = "dpipe-header-id", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_DPIPE_HEADER_GLOBAL] = { .name = "dpipe-header-global", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_DPIPE_HEADER_INDEX] = { .name = "dpipe-header-index", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_DPIPE_FIELD_ID] = { .name = "dpipe-field-id", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest devlink_dl_dpipe_match_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_dpipe_match_policy,
};

const struct ynl_policy_attr devlink_dl_dpipe_match_value_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_DPIPE_MATCH] = { .name = "dpipe-match", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_match_nest, },
	[DEVLINK_ATTR_DPIPE_VALUE] = { .name = "dpipe-value", .type = YNL_PT_BINARY,},
	[DEVLINK_ATTR_DPIPE_VALUE_MASK] = { .name = "dpipe-value-mask", .type = YNL_PT_BINARY,},
	[DEVLINK_ATTR_DPIPE_VALUE_MAPPING] = { .name = "dpipe-value-mapping", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest devlink_dl_dpipe_match_value_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_dpipe_match_value_policy,
};

const struct ynl_policy_attr devlink_dl_dpipe_action_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_DPIPE_ACTION_TYPE] = { .name = "dpipe-action-type", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_DPIPE_HEADER_ID] = { .name = "dpipe-header-id", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_DPIPE_HEADER_GLOBAL] = { .name = "dpipe-header-global", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_DPIPE_HEADER_INDEX] = { .name = "dpipe-header-index", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_DPIPE_FIELD_ID] = { .name = "dpipe-field-id", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest devlink_dl_dpipe_action_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_dpipe_action_policy,
};

const struct ynl_policy_attr devlink_dl_dpipe_action_value_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_DPIPE_ACTION] = { .name = "dpipe-action", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_action_nest, },
	[DEVLINK_ATTR_DPIPE_VALUE] = { .name = "dpipe-value", .type = YNL_PT_BINARY,},
	[DEVLINK_ATTR_DPIPE_VALUE_MASK] = { .name = "dpipe-value-mask", .type = YNL_PT_BINARY,},
	[DEVLINK_ATTR_DPIPE_VALUE_MAPPING] = { .name = "dpipe-value-mapping", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest devlink_dl_dpipe_action_value_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_dpipe_action_value_policy,
};

const struct ynl_policy_attr devlink_dl_dpipe_field_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_DPIPE_FIELD_NAME] = { .name = "dpipe-field-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_DPIPE_FIELD_ID] = { .name = "dpipe-field-id", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH] = { .name = "dpipe-field-bitwidth", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE] = { .name = "dpipe-field-mapping-type", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest devlink_dl_dpipe_field_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_dpipe_field_policy,
};

const struct ynl_policy_attr devlink_dl_resource_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_RESOURCE_NAME] = { .name = "resource-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_RESOURCE_ID] = { .name = "resource-id", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_RESOURCE_SIZE] = { .name = "resource-size", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_RESOURCE_SIZE_NEW] = { .name = "resource-size-new", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_RESOURCE_SIZE_VALID] = { .name = "resource-size-valid", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_RESOURCE_SIZE_MIN] = { .name = "resource-size-min", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_RESOURCE_SIZE_MAX] = { .name = "resource-size-max", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_RESOURCE_SIZE_GRAN] = { .name = "resource-size-gran", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_RESOURCE_UNIT] = { .name = "resource-unit", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_RESOURCE_OCC] = { .name = "resource-occ", .type = YNL_PT_U64, },
};

const struct ynl_policy_nest devlink_dl_resource_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_resource_policy,
};

const struct ynl_policy_attr devlink_dl_param_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_PARAM_NAME] = { .name = "param-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_PARAM_GENERIC] = { .name = "param-generic", .type = YNL_PT_FLAG, },
	[DEVLINK_ATTR_PARAM_TYPE] = { .name = "param-type", .type = YNL_PT_U8, },
};

const struct ynl_policy_nest devlink_dl_param_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_param_policy,
};

const struct ynl_policy_attr devlink_dl_region_snapshot_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_REGION_SNAPSHOT_ID] = { .name = "region-snapshot-id", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest devlink_dl_region_snapshot_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_region_snapshot_policy,
};

const struct ynl_policy_attr devlink_dl_region_chunk_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_REGION_CHUNK_DATA] = { .name = "region-chunk-data", .type = YNL_PT_BINARY,},
	[DEVLINK_ATTR_REGION_CHUNK_ADDR] = { .name = "region-chunk-addr", .type = YNL_PT_U64, },
};

const struct ynl_policy_nest devlink_dl_region_chunk_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_region_chunk_policy,
};

const struct ynl_policy_attr devlink_dl_info_version_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_INFO_VERSION_NAME] = { .name = "info-version-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_INFO_VERSION_VALUE] = { .name = "info-version-value", .type = YNL_PT_NUL_STR, },
};

const struct ynl_policy_nest devlink_dl_info_version_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_info_version_policy,
};

const struct ynl_policy_attr devlink_dl_fmsg_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_FMSG_OBJ_NEST_START] = { .name = "fmsg-obj-nest-start", .type = YNL_PT_FLAG, },
	[DEVLINK_ATTR_FMSG_PAIR_NEST_START] = { .name = "fmsg-pair-nest-start", .type = YNL_PT_FLAG, },
	[DEVLINK_ATTR_FMSG_ARR_NEST_START] = { .name = "fmsg-arr-nest-start", .type = YNL_PT_FLAG, },
	[DEVLINK_ATTR_FMSG_NEST_END] = { .name = "fmsg-nest-end", .type = YNL_PT_FLAG, },
	[DEVLINK_ATTR_FMSG_OBJ_NAME] = { .name = "fmsg-obj-name", .type = YNL_PT_NUL_STR, },
};

const struct ynl_policy_nest devlink_dl_fmsg_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_fmsg_policy,
};

const struct ynl_policy_attr devlink_dl_health_reporter_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_HEALTH_REPORTER_NAME] = { .name = "health-reporter-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_HEALTH_REPORTER_STATE] = { .name = "health-reporter-state", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT] = { .name = "health-reporter-err-count", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT] = { .name = "health-reporter-recover-count", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD] = { .name = "health-reporter-graceful-period", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER] = { .name = "health-reporter-auto-recover", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS] = { .name = "health-reporter-dump-ts", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS_NS] = { .name = "health-reporter-dump-ts-ns", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP] = { .name = "health-reporter-auto-dump", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_HEALTH_REPORTER_BURST_PERIOD] = { .name = "health-reporter-burst-period", .type = YNL_PT_U64, },
};

const struct ynl_policy_nest devlink_dl_health_reporter_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_health_reporter_policy,
};

const struct ynl_policy_attr devlink_dl_attr_stats_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_STATS_RX_PACKETS] = { .name = "stats-rx-packets", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_STATS_RX_BYTES] = { .name = "stats-rx-bytes", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_STATS_RX_DROPPED] = { .name = "stats-rx-dropped", .type = YNL_PT_U64, },
};

const struct ynl_policy_nest devlink_dl_attr_stats_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_attr_stats_policy,
};

const struct ynl_policy_attr devlink_dl_trap_metadata_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_TRAP_METADATA_TYPE_IN_PORT] = { .name = "trap-metadata-type-in-port", .type = YNL_PT_FLAG, },
	[DEVLINK_ATTR_TRAP_METADATA_TYPE_FA_COOKIE] = { .name = "trap-metadata-type-fa-cookie", .type = YNL_PT_FLAG, },
};

const struct ynl_policy_nest devlink_dl_trap_metadata_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_trap_metadata_policy,
};

const struct ynl_policy_attr devlink_dl_port_function_policy[DEVLINK_PORT_FUNCTION_ATTR_MAX + 1] = {
	[DEVLINK_PORT_FUNCTION_ATTR_HW_ADDR] = { .name = "hw-addr", .type = YNL_PT_BINARY,},
	[DEVLINK_PORT_FN_ATTR_STATE] = { .name = "state", .type = YNL_PT_U8, },
	[DEVLINK_PORT_FN_ATTR_OPSTATE] = { .name = "opstate", .type = YNL_PT_U8, },
	[DEVLINK_PORT_FN_ATTR_CAPS] = { .name = "caps", .type = YNL_PT_BITFIELD32, },
};

const struct ynl_policy_nest devlink_dl_port_function_nest = {
	.max_attr = DEVLINK_PORT_FUNCTION_ATTR_MAX,
	.table = devlink_dl_port_function_policy,
};

const struct ynl_policy_attr devlink_dl_reload_stats_entry_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_RELOAD_STATS_LIMIT] = { .name = "reload-stats-limit", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_RELOAD_STATS_VALUE] = { .name = "reload-stats-value", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest devlink_dl_reload_stats_entry_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_reload_stats_entry_policy,
};

const struct ynl_policy_attr devlink_dl_reload_act_stats_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_RELOAD_STATS_ENTRY] = { .name = "reload-stats-entry", .type = YNL_PT_NEST, .nest = &devlink_dl_reload_stats_entry_nest, },
};

const struct ynl_policy_nest devlink_dl_reload_act_stats_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_reload_act_stats_policy,
};

const struct ynl_policy_attr devlink_dl_linecard_supported_types_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_LINECARD_TYPE] = { .name = "linecard-type", .type = YNL_PT_NUL_STR, },
};

const struct ynl_policy_nest devlink_dl_linecard_supported_types_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_linecard_supported_types_policy,
};

const struct ynl_policy_attr devlink_dl_selftest_id_policy[DEVLINK_ATTR_SELFTEST_ID_MAX + 1] = {
	[DEVLINK_ATTR_SELFTEST_ID_FLASH] = { .name = "flash", .type = YNL_PT_FLAG, },
};

const struct ynl_policy_nest devlink_dl_selftest_id_nest = {
	.max_attr = DEVLINK_ATTR_SELFTEST_ID_MAX,
	.table = devlink_dl_selftest_id_policy,
};

const struct ynl_policy_attr devlink_dl_rate_tc_bws_policy[DEVLINK_RATE_TC_ATTR_MAX + 1] = {
	[DEVLINK_RATE_TC_ATTR_INDEX] = { .name = "index", .type = YNL_PT_U8, },
	[DEVLINK_RATE_TC_ATTR_BW] = { .name = "bw", .type = YNL_PT_U32, },
};

const struct ynl_policy_nest devlink_dl_rate_tc_bws_nest = {
	.max_attr = DEVLINK_RATE_TC_ATTR_MAX,
	.table = devlink_dl_rate_tc_bws_policy,
};

const struct ynl_policy_attr devlink_dl_dpipe_table_matches_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_DPIPE_MATCH] = { .name = "dpipe-match", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_match_nest, },
};

const struct ynl_policy_nest devlink_dl_dpipe_table_matches_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_dpipe_table_matches_policy,
};

const struct ynl_policy_attr devlink_dl_dpipe_table_actions_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_DPIPE_ACTION] = { .name = "dpipe-action", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_action_nest, },
};

const struct ynl_policy_nest devlink_dl_dpipe_table_actions_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_dpipe_table_actions_policy,
};

const struct ynl_policy_attr devlink_dl_dpipe_entry_match_values_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_DPIPE_MATCH_VALUE] = { .name = "dpipe-match-value", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_match_value_nest, },
};

const struct ynl_policy_nest devlink_dl_dpipe_entry_match_values_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_dpipe_entry_match_values_policy,
};

const struct ynl_policy_attr devlink_dl_dpipe_entry_action_values_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_DPIPE_ACTION_VALUE] = { .name = "dpipe-action-value", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_action_value_nest, },
};

const struct ynl_policy_nest devlink_dl_dpipe_entry_action_values_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_dpipe_entry_action_values_policy,
};

const struct ynl_policy_attr devlink_dl_dpipe_header_fields_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_DPIPE_FIELD] = { .name = "dpipe-field", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_field_nest, },
};

const struct ynl_policy_nest devlink_dl_dpipe_header_fields_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_dpipe_header_fields_policy,
};

const struct ynl_policy_attr devlink_dl_resource_list_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_RESOURCE] = { .name = "resource", .type = YNL_PT_NEST, .nest = &devlink_dl_resource_nest, },
};

const struct ynl_policy_nest devlink_dl_resource_list_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_resource_list_policy,
};

const struct ynl_policy_attr devlink_dl_region_snapshots_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_REGION_SNAPSHOT] = { .name = "region-snapshot", .type = YNL_PT_NEST, .nest = &devlink_dl_region_snapshot_nest, },
};

const struct ynl_policy_nest devlink_dl_region_snapshots_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_region_snapshots_policy,
};

const struct ynl_policy_attr devlink_dl_region_chunks_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_REGION_CHUNK] = { .name = "region-chunk", .type = YNL_PT_NEST, .nest = &devlink_dl_region_chunk_nest, },
};

const struct ynl_policy_nest devlink_dl_region_chunks_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_region_chunks_policy,
};

const struct ynl_policy_attr devlink_dl_reload_act_info_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_RELOAD_ACTION] = { .name = "reload-action", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_RELOAD_ACTION_STATS] = { .name = "reload-action-stats", .type = YNL_PT_NEST, .nest = &devlink_dl_reload_act_stats_nest, },
};

const struct ynl_policy_nest devlink_dl_reload_act_info_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_reload_act_info_policy,
};

const struct ynl_policy_attr devlink_dl_dpipe_table_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_DPIPE_TABLE_NAME] = { .name = "dpipe-table-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_DPIPE_TABLE_SIZE] = { .name = "dpipe-table-size", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_DPIPE_TABLE_MATCHES] = { .name = "dpipe-table-matches", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_table_matches_nest, },
	[DEVLINK_ATTR_DPIPE_TABLE_ACTIONS] = { .name = "dpipe-table-actions", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_table_actions_nest, },
	[DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED] = { .name = "dpipe-table-counters-enabled", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_ID] = { .name = "dpipe-table-resource-id", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_UNITS] = { .name = "dpipe-table-resource-units", .type = YNL_PT_U64, },
};

const struct ynl_policy_nest devlink_dl_dpipe_table_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_dpipe_table_policy,
};

const struct ynl_policy_attr devlink_dl_dpipe_entry_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_DPIPE_ENTRY_INDEX] = { .name = "dpipe-entry-index", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES] = { .name = "dpipe-entry-match-values", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_entry_match_values_nest, },
	[DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES] = { .name = "dpipe-entry-action-values", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_entry_action_values_nest, },
	[DEVLINK_ATTR_DPIPE_ENTRY_COUNTER] = { .name = "dpipe-entry-counter", .type = YNL_PT_U64, },
};

const struct ynl_policy_nest devlink_dl_dpipe_entry_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_dpipe_entry_policy,
};

const struct ynl_policy_attr devlink_dl_dpipe_header_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_DPIPE_HEADER_NAME] = { .name = "dpipe-header-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_DPIPE_HEADER_ID] = { .name = "dpipe-header-id", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_DPIPE_HEADER_GLOBAL] = { .name = "dpipe-header-global", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_DPIPE_HEADER_FIELDS] = { .name = "dpipe-header-fields", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_header_fields_nest, },
};

const struct ynl_policy_nest devlink_dl_dpipe_header_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_dpipe_header_policy,
};

const struct ynl_policy_attr devlink_dl_reload_stats_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_RELOAD_ACTION_INFO] = { .name = "reload-action-info", .type = YNL_PT_NEST, .nest = &devlink_dl_reload_act_info_nest, },
};

const struct ynl_policy_nest devlink_dl_reload_stats_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_reload_stats_policy,
};

const struct ynl_policy_attr devlink_dl_dpipe_tables_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_DPIPE_TABLE] = { .name = "dpipe-table", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_table_nest, },
};

const struct ynl_policy_nest devlink_dl_dpipe_tables_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_dpipe_tables_policy,
};

const struct ynl_policy_attr devlink_dl_dpipe_entries_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_DPIPE_ENTRY] = { .name = "dpipe-entry", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_entry_nest, },
};

const struct ynl_policy_nest devlink_dl_dpipe_entries_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_dpipe_entries_policy,
};

const struct ynl_policy_attr devlink_dl_dpipe_headers_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_DPIPE_HEADER] = { .name = "dpipe-header", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_header_nest, },
};

const struct ynl_policy_nest devlink_dl_dpipe_headers_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_dpipe_headers_policy,
};

const struct ynl_policy_attr devlink_dl_dev_stats_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_RELOAD_STATS] = { .name = "reload-stats", .type = YNL_PT_NEST, .nest = &devlink_dl_reload_stats_nest, },
	[DEVLINK_ATTR_REMOTE_RELOAD_STATS] = { .name = "remote-reload-stats", .type = YNL_PT_NEST, .nest = &devlink_dl_reload_stats_nest, },
};

const struct ynl_policy_nest devlink_dl_dev_stats_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_dl_dev_stats_policy,
};

const struct ynl_policy_attr devlink_policy[DEVLINK_ATTR_MAX + 1] = {
	[DEVLINK_ATTR_BUS_NAME] = { .name = "bus-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_DEV_NAME] = { .name = "dev-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_PORT_INDEX] = { .name = "port-index", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_PORT_TYPE] = { .name = "port-type", .type = YNL_PT_U16, },
	[DEVLINK_ATTR_PORT_DESIRED_TYPE] = { .name = "port-desired-type", .type = YNL_PT_U16, },
	[DEVLINK_ATTR_PORT_NETDEV_IFINDEX] = { .name = "port-netdev-ifindex", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_PORT_NETDEV_NAME] = { .name = "port-netdev-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_PORT_IBDEV_NAME] = { .name = "port-ibdev-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_PORT_SPLIT_COUNT] = { .name = "port-split-count", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_PORT_SPLIT_GROUP] = { .name = "port-split-group", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_SB_INDEX] = { .name = "sb-index", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_SB_SIZE] = { .name = "sb-size", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_SB_INGRESS_POOL_COUNT] = { .name = "sb-ingress-pool-count", .type = YNL_PT_U16, },
	[DEVLINK_ATTR_SB_EGRESS_POOL_COUNT] = { .name = "sb-egress-pool-count", .type = YNL_PT_U16, },
	[DEVLINK_ATTR_SB_INGRESS_TC_COUNT] = { .name = "sb-ingress-tc-count", .type = YNL_PT_U16, },
	[DEVLINK_ATTR_SB_EGRESS_TC_COUNT] = { .name = "sb-egress-tc-count", .type = YNL_PT_U16, },
	[DEVLINK_ATTR_SB_POOL_INDEX] = { .name = "sb-pool-index", .type = YNL_PT_U16, },
	[DEVLINK_ATTR_SB_POOL_TYPE] = { .name = "sb-pool-type", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_SB_POOL_SIZE] = { .name = "sb-pool-size", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE] = { .name = "sb-pool-threshold-type", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_SB_THRESHOLD] = { .name = "sb-threshold", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_SB_TC_INDEX] = { .name = "sb-tc-index", .type = YNL_PT_U16, },
	[DEVLINK_ATTR_SB_OCC_CUR] = { .name = "sb-occ-cur", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_SB_OCC_MAX] = { .name = "sb-occ-max", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_ESWITCH_MODE] = { .name = "eswitch-mode", .type = YNL_PT_U16, },
	[DEVLINK_ATTR_ESWITCH_INLINE_MODE] = { .name = "eswitch-inline-mode", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_DPIPE_TABLES] = { .name = "dpipe-tables", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_tables_nest, },
	[DEVLINK_ATTR_DPIPE_TABLE] = { .name = "dpipe-table", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_table_nest, },
	[DEVLINK_ATTR_DPIPE_TABLE_NAME] = { .name = "dpipe-table-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_DPIPE_TABLE_SIZE] = { .name = "dpipe-table-size", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_DPIPE_TABLE_MATCHES] = { .name = "dpipe-table-matches", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_table_matches_nest, },
	[DEVLINK_ATTR_DPIPE_TABLE_ACTIONS] = { .name = "dpipe-table-actions", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_table_actions_nest, },
	[DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED] = { .name = "dpipe-table-counters-enabled", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_DPIPE_ENTRIES] = { .name = "dpipe-entries", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_entries_nest, },
	[DEVLINK_ATTR_DPIPE_ENTRY] = { .name = "dpipe-entry", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_entry_nest, },
	[DEVLINK_ATTR_DPIPE_ENTRY_INDEX] = { .name = "dpipe-entry-index", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES] = { .name = "dpipe-entry-match-values", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_entry_match_values_nest, },
	[DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES] = { .name = "dpipe-entry-action-values", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_entry_action_values_nest, },
	[DEVLINK_ATTR_DPIPE_ENTRY_COUNTER] = { .name = "dpipe-entry-counter", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_DPIPE_MATCH] = { .name = "dpipe-match", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_match_nest, },
	[DEVLINK_ATTR_DPIPE_MATCH_VALUE] = { .name = "dpipe-match-value", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_match_value_nest, },
	[DEVLINK_ATTR_DPIPE_MATCH_TYPE] = { .name = "dpipe-match-type", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_DPIPE_ACTION] = { .name = "dpipe-action", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_action_nest, },
	[DEVLINK_ATTR_DPIPE_ACTION_VALUE] = { .name = "dpipe-action-value", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_action_value_nest, },
	[DEVLINK_ATTR_DPIPE_ACTION_TYPE] = { .name = "dpipe-action-type", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_DPIPE_VALUE] = { .name = "dpipe-value", .type = YNL_PT_BINARY,},
	[DEVLINK_ATTR_DPIPE_VALUE_MASK] = { .name = "dpipe-value-mask", .type = YNL_PT_BINARY,},
	[DEVLINK_ATTR_DPIPE_VALUE_MAPPING] = { .name = "dpipe-value-mapping", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_DPIPE_HEADERS] = { .name = "dpipe-headers", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_headers_nest, },
	[DEVLINK_ATTR_DPIPE_HEADER] = { .name = "dpipe-header", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_header_nest, },
	[DEVLINK_ATTR_DPIPE_HEADER_NAME] = { .name = "dpipe-header-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_DPIPE_HEADER_ID] = { .name = "dpipe-header-id", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_DPIPE_HEADER_FIELDS] = { .name = "dpipe-header-fields", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_header_fields_nest, },
	[DEVLINK_ATTR_DPIPE_HEADER_GLOBAL] = { .name = "dpipe-header-global", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_DPIPE_HEADER_INDEX] = { .name = "dpipe-header-index", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_DPIPE_FIELD] = { .name = "dpipe-field", .type = YNL_PT_NEST, .nest = &devlink_dl_dpipe_field_nest, },
	[DEVLINK_ATTR_DPIPE_FIELD_NAME] = { .name = "dpipe-field-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_DPIPE_FIELD_ID] = { .name = "dpipe-field-id", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH] = { .name = "dpipe-field-bitwidth", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE] = { .name = "dpipe-field-mapping-type", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_PAD] = { .name = "pad", .type = YNL_PT_IGNORE, },
	[DEVLINK_ATTR_ESWITCH_ENCAP_MODE] = { .name = "eswitch-encap-mode", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_RESOURCE_LIST] = { .name = "resource-list", .type = YNL_PT_NEST, .nest = &devlink_dl_resource_list_nest, },
	[DEVLINK_ATTR_RESOURCE] = { .name = "resource", .type = YNL_PT_NEST, .nest = &devlink_dl_resource_nest, },
	[DEVLINK_ATTR_RESOURCE_NAME] = { .name = "resource-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_RESOURCE_ID] = { .name = "resource-id", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_RESOURCE_SIZE] = { .name = "resource-size", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_RESOURCE_SIZE_NEW] = { .name = "resource-size-new", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_RESOURCE_SIZE_VALID] = { .name = "resource-size-valid", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_RESOURCE_SIZE_MIN] = { .name = "resource-size-min", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_RESOURCE_SIZE_MAX] = { .name = "resource-size-max", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_RESOURCE_SIZE_GRAN] = { .name = "resource-size-gran", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_RESOURCE_UNIT] = { .name = "resource-unit", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_RESOURCE_OCC] = { .name = "resource-occ", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_ID] = { .name = "dpipe-table-resource-id", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_UNITS] = { .name = "dpipe-table-resource-units", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_PORT_FLAVOUR] = { .name = "port-flavour", .type = YNL_PT_U16, },
	[DEVLINK_ATTR_PORT_NUMBER] = { .name = "port-number", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER] = { .name = "port-split-subport-number", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_PARAM] = { .name = "param", .type = YNL_PT_NEST, .nest = &devlink_dl_param_nest, },
	[DEVLINK_ATTR_PARAM_NAME] = { .name = "param-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_PARAM_GENERIC] = { .name = "param-generic", .type = YNL_PT_FLAG, },
	[DEVLINK_ATTR_PARAM_TYPE] = { .name = "param-type", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_PARAM_VALUE_CMODE] = { .name = "param-value-cmode", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_REGION_NAME] = { .name = "region-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_REGION_SIZE] = { .name = "region-size", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_REGION_SNAPSHOTS] = { .name = "region-snapshots", .type = YNL_PT_NEST, .nest = &devlink_dl_region_snapshots_nest, },
	[DEVLINK_ATTR_REGION_SNAPSHOT] = { .name = "region-snapshot", .type = YNL_PT_NEST, .nest = &devlink_dl_region_snapshot_nest, },
	[DEVLINK_ATTR_REGION_SNAPSHOT_ID] = { .name = "region-snapshot-id", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_REGION_CHUNKS] = { .name = "region-chunks", .type = YNL_PT_NEST, .nest = &devlink_dl_region_chunks_nest, },
	[DEVLINK_ATTR_REGION_CHUNK] = { .name = "region-chunk", .type = YNL_PT_NEST, .nest = &devlink_dl_region_chunk_nest, },
	[DEVLINK_ATTR_REGION_CHUNK_DATA] = { .name = "region-chunk-data", .type = YNL_PT_BINARY,},
	[DEVLINK_ATTR_REGION_CHUNK_ADDR] = { .name = "region-chunk-addr", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_REGION_CHUNK_LEN] = { .name = "region-chunk-len", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_INFO_DRIVER_NAME] = { .name = "info-driver-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_INFO_SERIAL_NUMBER] = { .name = "info-serial-number", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_INFO_VERSION_FIXED] = { .name = "info-version-fixed", .type = YNL_PT_NEST, .nest = &devlink_dl_info_version_nest, },
	[DEVLINK_ATTR_INFO_VERSION_RUNNING] = { .name = "info-version-running", .type = YNL_PT_NEST, .nest = &devlink_dl_info_version_nest, },
	[DEVLINK_ATTR_INFO_VERSION_STORED] = { .name = "info-version-stored", .type = YNL_PT_NEST, .nest = &devlink_dl_info_version_nest, },
	[DEVLINK_ATTR_INFO_VERSION_NAME] = { .name = "info-version-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_INFO_VERSION_VALUE] = { .name = "info-version-value", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_SB_POOL_CELL_SIZE] = { .name = "sb-pool-cell-size", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_FMSG] = { .name = "fmsg", .type = YNL_PT_NEST, .nest = &devlink_dl_fmsg_nest, },
	[DEVLINK_ATTR_FMSG_OBJ_NEST_START] = { .name = "fmsg-obj-nest-start", .type = YNL_PT_FLAG, },
	[DEVLINK_ATTR_FMSG_PAIR_NEST_START] = { .name = "fmsg-pair-nest-start", .type = YNL_PT_FLAG, },
	[DEVLINK_ATTR_FMSG_ARR_NEST_START] = { .name = "fmsg-arr-nest-start", .type = YNL_PT_FLAG, },
	[DEVLINK_ATTR_FMSG_NEST_END] = { .name = "fmsg-nest-end", .type = YNL_PT_FLAG, },
	[DEVLINK_ATTR_FMSG_OBJ_NAME] = { .name = "fmsg-obj-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_FMSG_OBJ_VALUE_TYPE] = { .name = "fmsg-obj-value-type", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_HEALTH_REPORTER] = { .name = "health-reporter", .type = YNL_PT_NEST, .nest = &devlink_dl_health_reporter_nest, },
	[DEVLINK_ATTR_HEALTH_REPORTER_NAME] = { .name = "health-reporter-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_HEALTH_REPORTER_STATE] = { .name = "health-reporter-state", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT] = { .name = "health-reporter-err-count", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT] = { .name = "health-reporter-recover-count", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS] = { .name = "health-reporter-dump-ts", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD] = { .name = "health-reporter-graceful-period", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER] = { .name = "health-reporter-auto-recover", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME] = { .name = "flash-update-file-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_FLASH_UPDATE_COMPONENT] = { .name = "flash-update-component", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG] = { .name = "flash-update-status-msg", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE] = { .name = "flash-update-status-done", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL] = { .name = "flash-update-status-total", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_PORT_PCI_PF_NUMBER] = { .name = "port-pci-pf-number", .type = YNL_PT_U16, },
	[DEVLINK_ATTR_PORT_PCI_VF_NUMBER] = { .name = "port-pci-vf-number", .type = YNL_PT_U16, },
	[DEVLINK_ATTR_STATS] = { .name = "stats", .type = YNL_PT_NEST, .nest = &devlink_dl_attr_stats_nest, },
	[DEVLINK_ATTR_TRAP_NAME] = { .name = "trap-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_TRAP_ACTION] = { .name = "trap-action", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_TRAP_TYPE] = { .name = "trap-type", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_TRAP_GENERIC] = { .name = "trap-generic", .type = YNL_PT_FLAG, },
	[DEVLINK_ATTR_TRAP_METADATA] = { .name = "trap-metadata", .type = YNL_PT_NEST, .nest = &devlink_dl_trap_metadata_nest, },
	[DEVLINK_ATTR_TRAP_GROUP_NAME] = { .name = "trap-group-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_RELOAD_FAILED] = { .name = "reload-failed", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS_NS] = { .name = "health-reporter-dump-ts-ns", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_NETNS_FD] = { .name = "netns-fd", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_NETNS_PID] = { .name = "netns-pid", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_NETNS_ID] = { .name = "netns-id", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP] = { .name = "health-reporter-auto-dump", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_TRAP_POLICER_ID] = { .name = "trap-policer-id", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_TRAP_POLICER_RATE] = { .name = "trap-policer-rate", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_TRAP_POLICER_BURST] = { .name = "trap-policer-burst", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_PORT_FUNCTION] = { .name = "port-function", .type = YNL_PT_NEST, .nest = &devlink_dl_port_function_nest, },
	[DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER] = { .name = "info-board-serial-number", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_PORT_LANES] = { .name = "port-lanes", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_PORT_SPLITTABLE] = { .name = "port-splittable", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_PORT_EXTERNAL] = { .name = "port-external", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_PORT_CONTROLLER_NUMBER] = { .name = "port-controller-number", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_FLASH_UPDATE_STATUS_TIMEOUT] = { .name = "flash-update-status-timeout", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_FLASH_UPDATE_OVERWRITE_MASK] = { .name = "flash-update-overwrite-mask", .type = YNL_PT_BITFIELD32, },
	[DEVLINK_ATTR_RELOAD_ACTION] = { .name = "reload-action", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_RELOAD_ACTIONS_PERFORMED] = { .name = "reload-actions-performed", .type = YNL_PT_BITFIELD32, },
	[DEVLINK_ATTR_RELOAD_LIMITS] = { .name = "reload-limits", .type = YNL_PT_BITFIELD32, },
	[DEVLINK_ATTR_DEV_STATS] = { .name = "dev-stats", .type = YNL_PT_NEST, .nest = &devlink_dl_dev_stats_nest, },
	[DEVLINK_ATTR_RELOAD_STATS] = { .name = "reload-stats", .type = YNL_PT_NEST, .nest = &devlink_dl_reload_stats_nest, },
	[DEVLINK_ATTR_RELOAD_STATS_ENTRY] = { .name = "reload-stats-entry", .type = YNL_PT_NEST, .nest = &devlink_dl_reload_stats_entry_nest, },
	[DEVLINK_ATTR_RELOAD_STATS_LIMIT] = { .name = "reload-stats-limit", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_RELOAD_STATS_VALUE] = { .name = "reload-stats-value", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_REMOTE_RELOAD_STATS] = { .name = "remote-reload-stats", .type = YNL_PT_NEST, .nest = &devlink_dl_reload_stats_nest, },
	[DEVLINK_ATTR_RELOAD_ACTION_INFO] = { .name = "reload-action-info", .type = YNL_PT_NEST, .nest = &devlink_dl_reload_act_info_nest, },
	[DEVLINK_ATTR_RELOAD_ACTION_STATS] = { .name = "reload-action-stats", .type = YNL_PT_NEST, .nest = &devlink_dl_reload_act_stats_nest, },
	[DEVLINK_ATTR_PORT_PCI_SF_NUMBER] = { .name = "port-pci-sf-number", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_RATE_TYPE] = { .name = "rate-type", .type = YNL_PT_U16, },
	[DEVLINK_ATTR_RATE_TX_SHARE] = { .name = "rate-tx-share", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_RATE_TX_MAX] = { .name = "rate-tx-max", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_RATE_NODE_NAME] = { .name = "rate-node-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_RATE_PARENT_NODE_NAME] = { .name = "rate-parent-node-name", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_REGION_MAX_SNAPSHOTS] = { .name = "region-max-snapshots", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_LINECARD_INDEX] = { .name = "linecard-index", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_LINECARD_STATE] = { .name = "linecard-state", .type = YNL_PT_U8, },
	[DEVLINK_ATTR_LINECARD_TYPE] = { .name = "linecard-type", .type = YNL_PT_NUL_STR, },
	[DEVLINK_ATTR_LINECARD_SUPPORTED_TYPES] = { .name = "linecard-supported-types", .type = YNL_PT_NEST, .nest = &devlink_dl_linecard_supported_types_nest, },
	[DEVLINK_ATTR_SELFTESTS] = { .name = "selftests", .type = YNL_PT_NEST, .nest = &devlink_dl_selftest_id_nest, },
	[DEVLINK_ATTR_RATE_TX_PRIORITY] = { .name = "rate-tx-priority", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_RATE_TX_WEIGHT] = { .name = "rate-tx-weight", .type = YNL_PT_U32, },
	[DEVLINK_ATTR_REGION_DIRECT] = { .name = "region-direct", .type = YNL_PT_FLAG, },
	[DEVLINK_ATTR_RATE_TC_BWS] = { .name = "rate-tc-bws", .type = YNL_PT_NEST, .nest = &devlink_dl_rate_tc_bws_nest, },
	[DEVLINK_ATTR_HEALTH_REPORTER_BURST_PERIOD] = { .name = "health-reporter-burst-period", .type = YNL_PT_U64, },
	[DEVLINK_ATTR_PARAM_RESET_DEFAULT] = { .name = "param-reset-default", .type = YNL_PT_FLAG, },
};

const struct ynl_policy_nest devlink_nest = {
	.max_attr = DEVLINK_ATTR_MAX,
	.table = devlink_policy,
};

/* Common nested types */
void devlink_dl_dpipe_match_free(struct devlink_dl_dpipe_match *obj)
{
}

int devlink_dl_dpipe_match_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	struct devlink_dl_dpipe_match *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_MATCH_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_match_type = 1;
			dst->dpipe_match_type = ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_HEADER_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_header_id = 1;
			dst->dpipe_header_id = ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_HEADER_GLOBAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_header_global = 1;
			dst->dpipe_header_global = ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_HEADER_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_header_index = 1;
			dst->dpipe_header_index = ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_FIELD_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_field_id = 1;
			dst->dpipe_field_id = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void
devlink_dl_dpipe_match_value_free(struct devlink_dl_dpipe_match_value *obj)
{
	unsigned int i;

	for (i = 0; i < obj->_count.dpipe_match; i++)
		devlink_dl_dpipe_match_free(&obj->dpipe_match[i]);
	free(obj->dpipe_match);
	free(obj->dpipe_value);
	free(obj->dpipe_value_mask);
}

int devlink_dl_dpipe_match_value_parse(struct ynl_parse_arg *yarg,
				       const struct nlattr *nested)
{
	struct devlink_dl_dpipe_match_value *dst = yarg->data;
	unsigned int n_dpipe_match = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_match)
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-match-value.dpipe-match)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_MATCH) {
			n_dpipe_match++;
		} else if (type == DEVLINK_ATTR_DPIPE_VALUE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.dpipe_value = len;
			dst->dpipe_value = malloc(len);
			memcpy(dst->dpipe_value, ynl_attr_data(attr), len);
		} else if (type == DEVLINK_ATTR_DPIPE_VALUE_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.dpipe_value_mask = len;
			dst->dpipe_value_mask = malloc(len);
			memcpy(dst->dpipe_value_mask, ynl_attr_data(attr), len);
		} else if (type == DEVLINK_ATTR_DPIPE_VALUE_MAPPING) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_value_mapping = 1;
			dst->dpipe_value_mapping = ynl_attr_get_u32(attr);
		}
	}

	if (n_dpipe_match) {
		dst->dpipe_match = calloc(n_dpipe_match, sizeof(*dst->dpipe_match));
		dst->_count.dpipe_match = n_dpipe_match;
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_match_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_MATCH) {
				parg.data = &dst->dpipe_match[i];
				if (devlink_dl_dpipe_match_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

void devlink_dl_dpipe_action_free(struct devlink_dl_dpipe_action *obj)
{
}

int devlink_dl_dpipe_action_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested)
{
	struct devlink_dl_dpipe_action *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_ACTION_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_action_type = 1;
			dst->dpipe_action_type = ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_HEADER_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_header_id = 1;
			dst->dpipe_header_id = ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_HEADER_GLOBAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_header_global = 1;
			dst->dpipe_header_global = ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_HEADER_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_header_index = 1;
			dst->dpipe_header_index = ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_FIELD_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_field_id = 1;
			dst->dpipe_field_id = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void
devlink_dl_dpipe_action_value_free(struct devlink_dl_dpipe_action_value *obj)
{
	unsigned int i;

	for (i = 0; i < obj->_count.dpipe_action; i++)
		devlink_dl_dpipe_action_free(&obj->dpipe_action[i]);
	free(obj->dpipe_action);
	free(obj->dpipe_value);
	free(obj->dpipe_value_mask);
}

int devlink_dl_dpipe_action_value_parse(struct ynl_parse_arg *yarg,
					const struct nlattr *nested)
{
	struct devlink_dl_dpipe_action_value *dst = yarg->data;
	unsigned int n_dpipe_action = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_action)
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-action-value.dpipe-action)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_ACTION) {
			n_dpipe_action++;
		} else if (type == DEVLINK_ATTR_DPIPE_VALUE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.dpipe_value = len;
			dst->dpipe_value = malloc(len);
			memcpy(dst->dpipe_value, ynl_attr_data(attr), len);
		} else if (type == DEVLINK_ATTR_DPIPE_VALUE_MASK) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = ynl_attr_data_len(attr);
			dst->_len.dpipe_value_mask = len;
			dst->dpipe_value_mask = malloc(len);
			memcpy(dst->dpipe_value_mask, ynl_attr_data(attr), len);
		} else if (type == DEVLINK_ATTR_DPIPE_VALUE_MAPPING) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_value_mapping = 1;
			dst->dpipe_value_mapping = ynl_attr_get_u32(attr);
		}
	}

	if (n_dpipe_action) {
		dst->dpipe_action = calloc(n_dpipe_action, sizeof(*dst->dpipe_action));
		dst->_count.dpipe_action = n_dpipe_action;
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_action_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_ACTION) {
				parg.data = &dst->dpipe_action[i];
				if (devlink_dl_dpipe_action_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

void devlink_dl_dpipe_field_free(struct devlink_dl_dpipe_field *obj)
{
	free(obj->dpipe_field_name);
}

int devlink_dl_dpipe_field_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	struct devlink_dl_dpipe_field *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_FIELD_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dpipe_field_name = len;
			dst->dpipe_field_name = malloc(len + 1);
			memcpy(dst->dpipe_field_name, ynl_attr_get_str(attr), len);
			dst->dpipe_field_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DPIPE_FIELD_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_field_id = 1;
			dst->dpipe_field_id = ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_field_bitwidth = 1;
			dst->dpipe_field_bitwidth = ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_field_mapping_type = 1;
			dst->dpipe_field_mapping_type = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void devlink_dl_resource_free(struct devlink_dl_resource *obj)
{
	free(obj->resource_name);
}

int devlink_dl_resource_parse(struct ynl_parse_arg *yarg,
			      const struct nlattr *nested)
{
	struct devlink_dl_resource *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_RESOURCE_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.resource_name = len;
			dst->resource_name = malloc(len + 1);
			memcpy(dst->resource_name, ynl_attr_get_str(attr), len);
			dst->resource_name[len] = 0;
		} else if (type == DEVLINK_ATTR_RESOURCE_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.resource_id = 1;
			dst->resource_id = ynl_attr_get_u64(attr);
		} else if (type == DEVLINK_ATTR_RESOURCE_SIZE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.resource_size = 1;
			dst->resource_size = ynl_attr_get_u64(attr);
		} else if (type == DEVLINK_ATTR_RESOURCE_SIZE_NEW) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.resource_size_new = 1;
			dst->resource_size_new = ynl_attr_get_u64(attr);
		} else if (type == DEVLINK_ATTR_RESOURCE_SIZE_VALID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.resource_size_valid = 1;
			dst->resource_size_valid = ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_RESOURCE_SIZE_MIN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.resource_size_min = 1;
			dst->resource_size_min = ynl_attr_get_u64(attr);
		} else if (type == DEVLINK_ATTR_RESOURCE_SIZE_MAX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.resource_size_max = 1;
			dst->resource_size_max = ynl_attr_get_u64(attr);
		} else if (type == DEVLINK_ATTR_RESOURCE_SIZE_GRAN) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.resource_size_gran = 1;
			dst->resource_size_gran = ynl_attr_get_u64(attr);
		} else if (type == DEVLINK_ATTR_RESOURCE_UNIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.resource_unit = 1;
			dst->resource_unit = ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_RESOURCE_OCC) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.resource_occ = 1;
			dst->resource_occ = ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

void devlink_dl_param_free(struct devlink_dl_param *obj)
{
	free(obj->param_name);
}

void devlink_dl_region_snapshot_free(struct devlink_dl_region_snapshot *obj)
{
}

void devlink_dl_region_chunk_free(struct devlink_dl_region_chunk *obj)
{
	free(obj->region_chunk_data);
}

void devlink_dl_info_version_free(struct devlink_dl_info_version *obj)
{
	free(obj->info_version_name);
	free(obj->info_version_value);
}

int devlink_dl_info_version_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested)
{
	struct devlink_dl_info_version *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_INFO_VERSION_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.info_version_name = len;
			dst->info_version_name = malloc(len + 1);
			memcpy(dst->info_version_name, ynl_attr_get_str(attr), len);
			dst->info_version_name[len] = 0;
		} else if (type == DEVLINK_ATTR_INFO_VERSION_VALUE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.info_version_value = len;
			dst->info_version_value = malloc(len + 1);
			memcpy(dst->info_version_value, ynl_attr_get_str(attr), len);
			dst->info_version_value[len] = 0;
		}
	}

	return 0;
}

void devlink_dl_fmsg_free(struct devlink_dl_fmsg *obj)
{
	free(obj->fmsg_obj_name);
}

int devlink_dl_fmsg_parse(struct ynl_parse_arg *yarg,
			  const struct nlattr *nested)
{
	struct devlink_dl_fmsg *dst = yarg->data;
	const struct nlattr *attr;
	unsigned int len;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_FMSG_OBJ_NEST_START) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fmsg_obj_nest_start = 1;
		} else if (type == DEVLINK_ATTR_FMSG_PAIR_NEST_START) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fmsg_pair_nest_start = 1;
		} else if (type == DEVLINK_ATTR_FMSG_ARR_NEST_START) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fmsg_arr_nest_start = 1;
		} else if (type == DEVLINK_ATTR_FMSG_NEST_END) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fmsg_nest_end = 1;
		} else if (type == DEVLINK_ATTR_FMSG_OBJ_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.fmsg_obj_name = len;
			dst->fmsg_obj_name = malloc(len + 1);
			memcpy(dst->fmsg_obj_name, ynl_attr_get_str(attr), len);
			dst->fmsg_obj_name[len] = 0;
		}
	}

	return 0;
}

void devlink_dl_health_reporter_free(struct devlink_dl_health_reporter *obj)
{
	free(obj->health_reporter_name);
}

void devlink_dl_attr_stats_free(struct devlink_dl_attr_stats *obj)
{
}

void devlink_dl_trap_metadata_free(struct devlink_dl_trap_metadata *obj)
{
}

void devlink_dl_port_function_free(struct devlink_dl_port_function *obj)
{
	free(obj->hw_addr);
}

int devlink_dl_port_function_put(struct nlmsghdr *nlh, unsigned int attr_type,
				 struct devlink_dl_port_function *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_len.hw_addr)
		ynl_attr_put(nlh, DEVLINK_PORT_FUNCTION_ATTR_HW_ADDR, obj->hw_addr, obj->_len.hw_addr);
	if (obj->_present.state)
		ynl_attr_put_u8(nlh, DEVLINK_PORT_FN_ATTR_STATE, obj->state);
	if (obj->_present.opstate)
		ynl_attr_put_u8(nlh, DEVLINK_PORT_FN_ATTR_OPSTATE, obj->opstate);
	if (obj->_present.caps)
		ynl_attr_put(nlh, DEVLINK_PORT_FN_ATTR_CAPS, &obj->caps, sizeof(struct nla_bitfield32));
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

void
devlink_dl_reload_stats_entry_free(struct devlink_dl_reload_stats_entry *obj)
{
}

int devlink_dl_reload_stats_entry_parse(struct ynl_parse_arg *yarg,
					const struct nlattr *nested)
{
	struct devlink_dl_reload_stats_entry *dst = yarg->data;
	const struct nlattr *attr;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_RELOAD_STATS_LIMIT) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.reload_stats_limit = 1;
			dst->reload_stats_limit = ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_RELOAD_STATS_VALUE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.reload_stats_value = 1;
			dst->reload_stats_value = ynl_attr_get_u32(attr);
		}
	}

	return 0;
}

void devlink_dl_reload_act_stats_free(struct devlink_dl_reload_act_stats *obj)
{
	unsigned int i;

	for (i = 0; i < obj->_count.reload_stats_entry; i++)
		devlink_dl_reload_stats_entry_free(&obj->reload_stats_entry[i]);
	free(obj->reload_stats_entry);
}

int devlink_dl_reload_act_stats_parse(struct ynl_parse_arg *yarg,
				      const struct nlattr *nested)
{
	struct devlink_dl_reload_act_stats *dst = yarg->data;
	unsigned int n_reload_stats_entry = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->reload_stats_entry)
		return ynl_error_parse(yarg, "attribute already present (dl-reload-act-stats.reload-stats-entry)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_RELOAD_STATS_ENTRY) {
			n_reload_stats_entry++;
		}
	}

	if (n_reload_stats_entry) {
		dst->reload_stats_entry = calloc(n_reload_stats_entry, sizeof(*dst->reload_stats_entry));
		dst->_count.reload_stats_entry = n_reload_stats_entry;
		i = 0;
		parg.rsp_policy = &devlink_dl_reload_stats_entry_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_RELOAD_STATS_ENTRY) {
				parg.data = &dst->reload_stats_entry[i];
				if (devlink_dl_reload_stats_entry_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

void
devlink_dl_linecard_supported_types_free(struct devlink_dl_linecard_supported_types *obj)
{
	free(obj->linecard_type);
}

void devlink_dl_selftest_id_free(struct devlink_dl_selftest_id *obj)
{
}

int devlink_dl_selftest_id_put(struct nlmsghdr *nlh, unsigned int attr_type,
			       struct devlink_dl_selftest_id *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.flash)
		ynl_attr_put(nlh, DEVLINK_ATTR_SELFTEST_ID_FLASH, NULL, 0);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

void devlink_dl_rate_tc_bws_free(struct devlink_dl_rate_tc_bws *obj)
{
}

int devlink_dl_rate_tc_bws_put(struct nlmsghdr *nlh, unsigned int attr_type,
			       struct devlink_dl_rate_tc_bws *obj)
{
	struct nlattr *nest;

	nest = ynl_attr_nest_start(nlh, attr_type);
	if (obj->_present.index)
		ynl_attr_put_u8(nlh, DEVLINK_RATE_TC_ATTR_INDEX, obj->index);
	if (obj->_present.bw)
		ynl_attr_put_u32(nlh, DEVLINK_RATE_TC_ATTR_BW, obj->bw);
	ynl_attr_nest_end(nlh, nest);

	return 0;
}

void
devlink_dl_dpipe_table_matches_free(struct devlink_dl_dpipe_table_matches *obj)
{
	unsigned int i;

	for (i = 0; i < obj->_count.dpipe_match; i++)
		devlink_dl_dpipe_match_free(&obj->dpipe_match[i]);
	free(obj->dpipe_match);
}

int devlink_dl_dpipe_table_matches_parse(struct ynl_parse_arg *yarg,
					 const struct nlattr *nested)
{
	struct devlink_dl_dpipe_table_matches *dst = yarg->data;
	unsigned int n_dpipe_match = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_match)
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-table-matches.dpipe-match)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_MATCH) {
			n_dpipe_match++;
		}
	}

	if (n_dpipe_match) {
		dst->dpipe_match = calloc(n_dpipe_match, sizeof(*dst->dpipe_match));
		dst->_count.dpipe_match = n_dpipe_match;
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_match_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_MATCH) {
				parg.data = &dst->dpipe_match[i];
				if (devlink_dl_dpipe_match_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

void
devlink_dl_dpipe_table_actions_free(struct devlink_dl_dpipe_table_actions *obj)
{
	unsigned int i;

	for (i = 0; i < obj->_count.dpipe_action; i++)
		devlink_dl_dpipe_action_free(&obj->dpipe_action[i]);
	free(obj->dpipe_action);
}

int devlink_dl_dpipe_table_actions_parse(struct ynl_parse_arg *yarg,
					 const struct nlattr *nested)
{
	struct devlink_dl_dpipe_table_actions *dst = yarg->data;
	unsigned int n_dpipe_action = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_action)
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-table-actions.dpipe-action)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_ACTION) {
			n_dpipe_action++;
		}
	}

	if (n_dpipe_action) {
		dst->dpipe_action = calloc(n_dpipe_action, sizeof(*dst->dpipe_action));
		dst->_count.dpipe_action = n_dpipe_action;
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_action_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_ACTION) {
				parg.data = &dst->dpipe_action[i];
				if (devlink_dl_dpipe_action_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

void
devlink_dl_dpipe_entry_match_values_free(struct devlink_dl_dpipe_entry_match_values *obj)
{
	unsigned int i;

	for (i = 0; i < obj->_count.dpipe_match_value; i++)
		devlink_dl_dpipe_match_value_free(&obj->dpipe_match_value[i]);
	free(obj->dpipe_match_value);
}

int devlink_dl_dpipe_entry_match_values_parse(struct ynl_parse_arg *yarg,
					      const struct nlattr *nested)
{
	struct devlink_dl_dpipe_entry_match_values *dst = yarg->data;
	unsigned int n_dpipe_match_value = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_match_value)
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-entry-match-values.dpipe-match-value)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_MATCH_VALUE) {
			n_dpipe_match_value++;
		}
	}

	if (n_dpipe_match_value) {
		dst->dpipe_match_value = calloc(n_dpipe_match_value, sizeof(*dst->dpipe_match_value));
		dst->_count.dpipe_match_value = n_dpipe_match_value;
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_match_value_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_MATCH_VALUE) {
				parg.data = &dst->dpipe_match_value[i];
				if (devlink_dl_dpipe_match_value_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

void
devlink_dl_dpipe_entry_action_values_free(struct devlink_dl_dpipe_entry_action_values *obj)
{
	unsigned int i;

	for (i = 0; i < obj->_count.dpipe_action_value; i++)
		devlink_dl_dpipe_action_value_free(&obj->dpipe_action_value[i]);
	free(obj->dpipe_action_value);
}

int devlink_dl_dpipe_entry_action_values_parse(struct ynl_parse_arg *yarg,
					       const struct nlattr *nested)
{
	struct devlink_dl_dpipe_entry_action_values *dst = yarg->data;
	unsigned int n_dpipe_action_value = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_action_value)
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-entry-action-values.dpipe-action-value)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_ACTION_VALUE) {
			n_dpipe_action_value++;
		}
	}

	if (n_dpipe_action_value) {
		dst->dpipe_action_value = calloc(n_dpipe_action_value, sizeof(*dst->dpipe_action_value));
		dst->_count.dpipe_action_value = n_dpipe_action_value;
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_action_value_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_ACTION_VALUE) {
				parg.data = &dst->dpipe_action_value[i];
				if (devlink_dl_dpipe_action_value_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

void
devlink_dl_dpipe_header_fields_free(struct devlink_dl_dpipe_header_fields *obj)
{
	unsigned int i;

	for (i = 0; i < obj->_count.dpipe_field; i++)
		devlink_dl_dpipe_field_free(&obj->dpipe_field[i]);
	free(obj->dpipe_field);
}

int devlink_dl_dpipe_header_fields_parse(struct ynl_parse_arg *yarg,
					 const struct nlattr *nested)
{
	struct devlink_dl_dpipe_header_fields *dst = yarg->data;
	unsigned int n_dpipe_field = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_field)
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-header-fields.dpipe-field)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_FIELD) {
			n_dpipe_field++;
		}
	}

	if (n_dpipe_field) {
		dst->dpipe_field = calloc(n_dpipe_field, sizeof(*dst->dpipe_field));
		dst->_count.dpipe_field = n_dpipe_field;
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_field_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_FIELD) {
				parg.data = &dst->dpipe_field[i];
				if (devlink_dl_dpipe_field_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

void devlink_dl_resource_list_free(struct devlink_dl_resource_list *obj)
{
	unsigned int i;

	for (i = 0; i < obj->_count.resource; i++)
		devlink_dl_resource_free(&obj->resource[i]);
	free(obj->resource);
}

int devlink_dl_resource_list_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested)
{
	struct devlink_dl_resource_list *dst = yarg->data;
	unsigned int n_resource = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->resource)
		return ynl_error_parse(yarg, "attribute already present (dl-resource-list.resource)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_RESOURCE) {
			n_resource++;
		}
	}

	if (n_resource) {
		dst->resource = calloc(n_resource, sizeof(*dst->resource));
		dst->_count.resource = n_resource;
		i = 0;
		parg.rsp_policy = &devlink_dl_resource_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_RESOURCE) {
				parg.data = &dst->resource[i];
				if (devlink_dl_resource_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

void devlink_dl_region_snapshots_free(struct devlink_dl_region_snapshots *obj)
{
	devlink_dl_region_snapshot_free(&obj->region_snapshot);
}

void devlink_dl_region_chunks_free(struct devlink_dl_region_chunks *obj)
{
	devlink_dl_region_chunk_free(&obj->region_chunk);
}

void devlink_dl_reload_act_info_free(struct devlink_dl_reload_act_info *obj)
{
	unsigned int i;

	for (i = 0; i < obj->_count.reload_action_stats; i++)
		devlink_dl_reload_act_stats_free(&obj->reload_action_stats[i]);
	free(obj->reload_action_stats);
}

int devlink_dl_reload_act_info_parse(struct ynl_parse_arg *yarg,
				     const struct nlattr *nested)
{
	struct devlink_dl_reload_act_info *dst = yarg->data;
	unsigned int n_reload_action_stats = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->reload_action_stats)
		return ynl_error_parse(yarg, "attribute already present (dl-reload-act-info.reload-action-stats)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_RELOAD_ACTION) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.reload_action = 1;
			dst->reload_action = ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_RELOAD_ACTION_STATS) {
			n_reload_action_stats++;
		}
	}

	if (n_reload_action_stats) {
		dst->reload_action_stats = calloc(n_reload_action_stats, sizeof(*dst->reload_action_stats));
		dst->_count.reload_action_stats = n_reload_action_stats;
		i = 0;
		parg.rsp_policy = &devlink_dl_reload_act_stats_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_RELOAD_ACTION_STATS) {
				parg.data = &dst->reload_action_stats[i];
				if (devlink_dl_reload_act_stats_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

void devlink_dl_dpipe_table_free(struct devlink_dl_dpipe_table *obj)
{
	free(obj->dpipe_table_name);
	devlink_dl_dpipe_table_matches_free(&obj->dpipe_table_matches);
	devlink_dl_dpipe_table_actions_free(&obj->dpipe_table_actions);
}

int devlink_dl_dpipe_table_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	struct devlink_dl_dpipe_table *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_TABLE_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dpipe_table_name = len;
			dst->dpipe_table_name = malloc(len + 1);
			memcpy(dst->dpipe_table_name, ynl_attr_get_str(attr), len);
			dst->dpipe_table_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DPIPE_TABLE_SIZE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_table_size = 1;
			dst->dpipe_table_size = ynl_attr_get_u64(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_TABLE_MATCHES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_table_matches = 1;

			parg.rsp_policy = &devlink_dl_dpipe_table_matches_nest;
			parg.data = &dst->dpipe_table_matches;
			if (devlink_dl_dpipe_table_matches_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == DEVLINK_ATTR_DPIPE_TABLE_ACTIONS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_table_actions = 1;

			parg.rsp_policy = &devlink_dl_dpipe_table_actions_nest;
			parg.data = &dst->dpipe_table_actions;
			if (devlink_dl_dpipe_table_actions_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_table_counters_enabled = 1;
			dst->dpipe_table_counters_enabled = ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_table_resource_id = 1;
			dst->dpipe_table_resource_id = ynl_attr_get_u64(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_UNITS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_table_resource_units = 1;
			dst->dpipe_table_resource_units = ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

void devlink_dl_dpipe_entry_free(struct devlink_dl_dpipe_entry *obj)
{
	devlink_dl_dpipe_entry_match_values_free(&obj->dpipe_entry_match_values);
	devlink_dl_dpipe_entry_action_values_free(&obj->dpipe_entry_action_values);
}

int devlink_dl_dpipe_entry_parse(struct ynl_parse_arg *yarg,
				 const struct nlattr *nested)
{
	struct devlink_dl_dpipe_entry *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_ENTRY_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_entry_index = 1;
			dst->dpipe_entry_index = ynl_attr_get_u64(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_entry_match_values = 1;

			parg.rsp_policy = &devlink_dl_dpipe_entry_match_values_nest;
			parg.data = &dst->dpipe_entry_match_values;
			if (devlink_dl_dpipe_entry_match_values_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_entry_action_values = 1;

			parg.rsp_policy = &devlink_dl_dpipe_entry_action_values_nest;
			parg.data = &dst->dpipe_entry_action_values;
			if (devlink_dl_dpipe_entry_action_values_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == DEVLINK_ATTR_DPIPE_ENTRY_COUNTER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_entry_counter = 1;
			dst->dpipe_entry_counter = ynl_attr_get_u64(attr);
		}
	}

	return 0;
}

void devlink_dl_dpipe_header_free(struct devlink_dl_dpipe_header *obj)
{
	free(obj->dpipe_header_name);
	devlink_dl_dpipe_header_fields_free(&obj->dpipe_header_fields);
}

int devlink_dl_dpipe_header_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested)
{
	struct devlink_dl_dpipe_header *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_HEADER_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dpipe_header_name = len;
			dst->dpipe_header_name = malloc(len + 1);
			memcpy(dst->dpipe_header_name, ynl_attr_get_str(attr), len);
			dst->dpipe_header_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DPIPE_HEADER_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_header_id = 1;
			dst->dpipe_header_id = ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_HEADER_GLOBAL) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_header_global = 1;
			dst->dpipe_header_global = ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_DPIPE_HEADER_FIELDS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_header_fields = 1;

			parg.rsp_policy = &devlink_dl_dpipe_header_fields_nest;
			parg.data = &dst->dpipe_header_fields;
			if (devlink_dl_dpipe_header_fields_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

void devlink_dl_reload_stats_free(struct devlink_dl_reload_stats *obj)
{
	unsigned int i;

	for (i = 0; i < obj->_count.reload_action_info; i++)
		devlink_dl_reload_act_info_free(&obj->reload_action_info[i]);
	free(obj->reload_action_info);
}

int devlink_dl_reload_stats_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested)
{
	struct devlink_dl_reload_stats *dst = yarg->data;
	unsigned int n_reload_action_info = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->reload_action_info)
		return ynl_error_parse(yarg, "attribute already present (dl-reload-stats.reload-action-info)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_RELOAD_ACTION_INFO) {
			n_reload_action_info++;
		}
	}

	if (n_reload_action_info) {
		dst->reload_action_info = calloc(n_reload_action_info, sizeof(*dst->reload_action_info));
		dst->_count.reload_action_info = n_reload_action_info;
		i = 0;
		parg.rsp_policy = &devlink_dl_reload_act_info_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_RELOAD_ACTION_INFO) {
				parg.data = &dst->reload_action_info[i];
				if (devlink_dl_reload_act_info_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

void devlink_dl_dpipe_tables_free(struct devlink_dl_dpipe_tables *obj)
{
	unsigned int i;

	for (i = 0; i < obj->_count.dpipe_table; i++)
		devlink_dl_dpipe_table_free(&obj->dpipe_table[i]);
	free(obj->dpipe_table);
}

int devlink_dl_dpipe_tables_parse(struct ynl_parse_arg *yarg,
				  const struct nlattr *nested)
{
	struct devlink_dl_dpipe_tables *dst = yarg->data;
	unsigned int n_dpipe_table = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_table)
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-tables.dpipe-table)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_TABLE) {
			n_dpipe_table++;
		}
	}

	if (n_dpipe_table) {
		dst->dpipe_table = calloc(n_dpipe_table, sizeof(*dst->dpipe_table));
		dst->_count.dpipe_table = n_dpipe_table;
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_table_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_TABLE) {
				parg.data = &dst->dpipe_table[i];
				if (devlink_dl_dpipe_table_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

void devlink_dl_dpipe_entries_free(struct devlink_dl_dpipe_entries *obj)
{
	unsigned int i;

	for (i = 0; i < obj->_count.dpipe_entry; i++)
		devlink_dl_dpipe_entry_free(&obj->dpipe_entry[i]);
	free(obj->dpipe_entry);
}

int devlink_dl_dpipe_entries_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested)
{
	struct devlink_dl_dpipe_entries *dst = yarg->data;
	unsigned int n_dpipe_entry = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_entry)
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-entries.dpipe-entry)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_ENTRY) {
			n_dpipe_entry++;
		}
	}

	if (n_dpipe_entry) {
		dst->dpipe_entry = calloc(n_dpipe_entry, sizeof(*dst->dpipe_entry));
		dst->_count.dpipe_entry = n_dpipe_entry;
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_entry_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_ENTRY) {
				parg.data = &dst->dpipe_entry[i];
				if (devlink_dl_dpipe_entry_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

void devlink_dl_dpipe_headers_free(struct devlink_dl_dpipe_headers *obj)
{
	unsigned int i;

	for (i = 0; i < obj->_count.dpipe_header; i++)
		devlink_dl_dpipe_header_free(&obj->dpipe_header[i]);
	free(obj->dpipe_header);
}

int devlink_dl_dpipe_headers_parse(struct ynl_parse_arg *yarg,
				   const struct nlattr *nested)
{
	struct devlink_dl_dpipe_headers *dst = yarg->data;
	unsigned int n_dpipe_header = 0;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	int i;

	parg.ys = yarg->ys;

	if (dst->dpipe_header)
		return ynl_error_parse(yarg, "attribute already present (dl-dpipe-headers.dpipe-header)");

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_DPIPE_HEADER) {
			n_dpipe_header++;
		}
	}

	if (n_dpipe_header) {
		dst->dpipe_header = calloc(n_dpipe_header, sizeof(*dst->dpipe_header));
		dst->_count.dpipe_header = n_dpipe_header;
		i = 0;
		parg.rsp_policy = &devlink_dl_dpipe_header_nest;
		ynl_attr_for_each_nested(attr, nested) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_DPIPE_HEADER) {
				parg.data = &dst->dpipe_header[i];
				if (devlink_dl_dpipe_header_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return 0;
}

void devlink_dl_dev_stats_free(struct devlink_dl_dev_stats *obj)
{
	devlink_dl_reload_stats_free(&obj->reload_stats);
	devlink_dl_reload_stats_free(&obj->remote_reload_stats);
}

int devlink_dl_dev_stats_parse(struct ynl_parse_arg *yarg,
			       const struct nlattr *nested)
{
	struct devlink_dl_dev_stats *dst = yarg->data;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	parg.ys = yarg->ys;

	ynl_attr_for_each_nested(attr, nested) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_RELOAD_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.reload_stats = 1;

			parg.rsp_policy = &devlink_dl_reload_stats_nest;
			parg.data = &dst->reload_stats;
			if (devlink_dl_reload_stats_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		} else if (type == DEVLINK_ATTR_REMOTE_RELOAD_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.remote_reload_stats = 1;

			parg.rsp_policy = &devlink_dl_reload_stats_nest;
			parg.data = &dst->remote_reload_stats;
			if (devlink_dl_reload_stats_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return 0;
}

/* ============== DEVLINK_CMD_GET ============== */
/* DEVLINK_CMD_GET - do */
void devlink_get_req_free(struct devlink_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_get_rsp_free(struct devlink_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	devlink_dl_dev_stats_free(&rsp->dev_stats);
	free(rsp);
}

int devlink_get_rsp_parse(const struct nlmsghdr *nlh,
			  struct ynl_parse_arg *yarg)
{
	struct devlink_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;

	dst = yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_RELOAD_FAILED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.reload_failed = 1;
			dst->reload_failed = ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_DEV_STATS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dev_stats = 1;

			parg.rsp_policy = &devlink_dl_dev_stats_nest;
			parg.data = &dst->dev_stats;
			if (devlink_dl_dev_stats_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_get_rsp *
devlink_get(struct ynl_sock *ys, struct devlink_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_get_rsp_parse;
	yrs.rsp_cmd = 3;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_get_rsp_free(rsp);
	return NULL;
}

/* DEVLINK_CMD_GET - dump */
void devlink_get_list_free(struct devlink_get_list *rsp)
{
	struct devlink_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.bus_name);
		free(rsp->obj.dev_name);
		devlink_dl_dev_stats_free(&rsp->obj.dev_stats);
		free(rsp);
	}
}

struct devlink_get_list *devlink_get_dump(struct ynl_sock *ys)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct devlink_get_list);
	yds.cb = devlink_get_rsp_parse;
	yds.rsp_cmd = 3;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, DEVLINK_CMD_GET, 1);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	devlink_get_list_free(yds.first);
	return NULL;
}

/* ============== DEVLINK_CMD_PORT_GET ============== */
/* DEVLINK_CMD_PORT_GET - do */
void devlink_port_get_req_free(struct devlink_port_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_port_get_rsp_free(struct devlink_port_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp);
}

int devlink_port_get_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	struct devlink_port_get_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.port_index = 1;
			dst->port_index = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_port_get_rsp *
devlink_port_get(struct ynl_sock *ys, struct devlink_port_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_port_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_PORT_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_port_get_rsp_parse;
	yrs.rsp_cmd = 7;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_port_get_rsp_free(rsp);
	return NULL;
}

/* DEVLINK_CMD_PORT_GET - dump */
int devlink_port_get_rsp_dump_parse(const struct nlmsghdr *nlh,
				    struct ynl_parse_arg *yarg)
{
	struct devlink_port_get_rsp_dump *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.port_index = 1;
			dst->port_index = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

void devlink_port_get_req_dump_free(struct devlink_port_get_req_dump *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_port_get_rsp_list_free(struct devlink_port_get_rsp_list *rsp)
{
	struct devlink_port_get_rsp_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.bus_name);
		free(rsp->obj.dev_name);
		free(rsp);
	}
}

struct devlink_port_get_rsp_list *
devlink_port_get_dump(struct ynl_sock *ys,
		      struct devlink_port_get_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct devlink_port_get_rsp_list);
	yds.cb = devlink_port_get_rsp_dump_parse;
	yds.rsp_cmd = 7;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, DEVLINK_CMD_PORT_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	devlink_port_get_rsp_list_free(yds.first);
	return NULL;
}

/* ============== DEVLINK_CMD_PORT_SET ============== */
/* DEVLINK_CMD_PORT_SET - do */
void devlink_port_set_req_free(struct devlink_port_set_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	devlink_dl_port_function_free(&req->port_function);
	free(req);
}

int devlink_port_set(struct ynl_sock *ys, struct devlink_port_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_PORT_SET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);
	if (req->_present.port_type)
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_PORT_TYPE, req->port_type);
	if (req->_present.port_function)
		devlink_dl_port_function_put(nlh, DEVLINK_ATTR_PORT_FUNCTION, &req->port_function);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_PORT_NEW ============== */
/* DEVLINK_CMD_PORT_NEW - do */
void devlink_port_new_req_free(struct devlink_port_new_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_port_new_rsp_free(struct devlink_port_new_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp);
}

int devlink_port_new_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	struct devlink_port_new_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.port_index = 1;
			dst->port_index = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_port_new_rsp *
devlink_port_new(struct ynl_sock *ys, struct devlink_port_new_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_port_new_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_PORT_NEW, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);
	if (req->_present.port_flavour)
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_PORT_FLAVOUR, req->port_flavour);
	if (req->_present.port_pci_pf_number)
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_PORT_PCI_PF_NUMBER, req->port_pci_pf_number);
	if (req->_present.port_pci_sf_number)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_PCI_SF_NUMBER, req->port_pci_sf_number);
	if (req->_present.port_controller_number)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_CONTROLLER_NUMBER, req->port_controller_number);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_port_new_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_PORT_NEW;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_port_new_rsp_free(rsp);
	return NULL;
}

/* ============== DEVLINK_CMD_PORT_DEL ============== */
/* DEVLINK_CMD_PORT_DEL - do */
void devlink_port_del_req_free(struct devlink_port_del_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

int devlink_port_del(struct ynl_sock *ys, struct devlink_port_del_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_PORT_DEL, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_PORT_SPLIT ============== */
/* DEVLINK_CMD_PORT_SPLIT - do */
void devlink_port_split_req_free(struct devlink_port_split_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

int devlink_port_split(struct ynl_sock *ys, struct devlink_port_split_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_PORT_SPLIT, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);
	if (req->_present.port_split_count)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_SPLIT_COUNT, req->port_split_count);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_PORT_UNSPLIT ============== */
/* DEVLINK_CMD_PORT_UNSPLIT - do */
void devlink_port_unsplit_req_free(struct devlink_port_unsplit_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

int devlink_port_unsplit(struct ynl_sock *ys,
			 struct devlink_port_unsplit_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_PORT_UNSPLIT, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_SB_GET ============== */
/* DEVLINK_CMD_SB_GET - do */
void devlink_sb_get_req_free(struct devlink_sb_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_sb_get_rsp_free(struct devlink_sb_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp);
}

int devlink_sb_get_rsp_parse(const struct nlmsghdr *nlh,
			     struct ynl_parse_arg *yarg)
{
	struct devlink_sb_get_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_SB_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sb_index = 1;
			dst->sb_index = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_sb_get_rsp *
devlink_sb_get(struct ynl_sock *ys, struct devlink_sb_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_sb_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_SB_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.sb_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_INDEX, req->sb_index);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_sb_get_rsp_parse;
	yrs.rsp_cmd = 13;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_sb_get_rsp_free(rsp);
	return NULL;
}

/* DEVLINK_CMD_SB_GET - dump */
void devlink_sb_get_req_dump_free(struct devlink_sb_get_req_dump *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_sb_get_list_free(struct devlink_sb_get_list *rsp)
{
	struct devlink_sb_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.bus_name);
		free(rsp->obj.dev_name);
		free(rsp);
	}
}

struct devlink_sb_get_list *
devlink_sb_get_dump(struct ynl_sock *ys, struct devlink_sb_get_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct devlink_sb_get_list);
	yds.cb = devlink_sb_get_rsp_parse;
	yds.rsp_cmd = 13;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, DEVLINK_CMD_SB_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	devlink_sb_get_list_free(yds.first);
	return NULL;
}

/* ============== DEVLINK_CMD_SB_POOL_GET ============== */
/* DEVLINK_CMD_SB_POOL_GET - do */
void devlink_sb_pool_get_req_free(struct devlink_sb_pool_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_sb_pool_get_rsp_free(struct devlink_sb_pool_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp);
}

int devlink_sb_pool_get_rsp_parse(const struct nlmsghdr *nlh,
				  struct ynl_parse_arg *yarg)
{
	struct devlink_sb_pool_get_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_SB_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sb_index = 1;
			dst->sb_index = ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_SB_POOL_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sb_pool_index = 1;
			dst->sb_pool_index = ynl_attr_get_u16(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_sb_pool_get_rsp *
devlink_sb_pool_get(struct ynl_sock *ys, struct devlink_sb_pool_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_sb_pool_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_SB_POOL_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.sb_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_INDEX, req->sb_index);
	if (req->_present.sb_pool_index)
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_SB_POOL_INDEX, req->sb_pool_index);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_sb_pool_get_rsp_parse;
	yrs.rsp_cmd = 17;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_sb_pool_get_rsp_free(rsp);
	return NULL;
}

/* DEVLINK_CMD_SB_POOL_GET - dump */
void
devlink_sb_pool_get_req_dump_free(struct devlink_sb_pool_get_req_dump *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_sb_pool_get_list_free(struct devlink_sb_pool_get_list *rsp)
{
	struct devlink_sb_pool_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.bus_name);
		free(rsp->obj.dev_name);
		free(rsp);
	}
}

struct devlink_sb_pool_get_list *
devlink_sb_pool_get_dump(struct ynl_sock *ys,
			 struct devlink_sb_pool_get_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct devlink_sb_pool_get_list);
	yds.cb = devlink_sb_pool_get_rsp_parse;
	yds.rsp_cmd = 17;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, DEVLINK_CMD_SB_POOL_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	devlink_sb_pool_get_list_free(yds.first);
	return NULL;
}

/* ============== DEVLINK_CMD_SB_POOL_SET ============== */
/* DEVLINK_CMD_SB_POOL_SET - do */
void devlink_sb_pool_set_req_free(struct devlink_sb_pool_set_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

int devlink_sb_pool_set(struct ynl_sock *ys,
			struct devlink_sb_pool_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_SB_POOL_SET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.sb_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_INDEX, req->sb_index);
	if (req->_present.sb_pool_index)
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_SB_POOL_INDEX, req->sb_pool_index);
	if (req->_present.sb_pool_threshold_type)
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE, req->sb_pool_threshold_type);
	if (req->_present.sb_pool_size)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_POOL_SIZE, req->sb_pool_size);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_SB_PORT_POOL_GET ============== */
/* DEVLINK_CMD_SB_PORT_POOL_GET - do */
void
devlink_sb_port_pool_get_req_free(struct devlink_sb_port_pool_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void
devlink_sb_port_pool_get_rsp_free(struct devlink_sb_port_pool_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp);
}

int devlink_sb_port_pool_get_rsp_parse(const struct nlmsghdr *nlh,
				       struct ynl_parse_arg *yarg)
{
	struct devlink_sb_port_pool_get_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.port_index = 1;
			dst->port_index = ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_SB_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sb_index = 1;
			dst->sb_index = ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_SB_POOL_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sb_pool_index = 1;
			dst->sb_pool_index = ynl_attr_get_u16(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_sb_port_pool_get_rsp *
devlink_sb_port_pool_get(struct ynl_sock *ys,
			 struct devlink_sb_port_pool_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_sb_port_pool_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_SB_PORT_POOL_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);
	if (req->_present.sb_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_INDEX, req->sb_index);
	if (req->_present.sb_pool_index)
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_SB_POOL_INDEX, req->sb_pool_index);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_sb_port_pool_get_rsp_parse;
	yrs.rsp_cmd = 21;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_sb_port_pool_get_rsp_free(rsp);
	return NULL;
}

/* DEVLINK_CMD_SB_PORT_POOL_GET - dump */
void
devlink_sb_port_pool_get_req_dump_free(struct devlink_sb_port_pool_get_req_dump *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void
devlink_sb_port_pool_get_list_free(struct devlink_sb_port_pool_get_list *rsp)
{
	struct devlink_sb_port_pool_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.bus_name);
		free(rsp->obj.dev_name);
		free(rsp);
	}
}

struct devlink_sb_port_pool_get_list *
devlink_sb_port_pool_get_dump(struct ynl_sock *ys,
			      struct devlink_sb_port_pool_get_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct devlink_sb_port_pool_get_list);
	yds.cb = devlink_sb_port_pool_get_rsp_parse;
	yds.rsp_cmd = 21;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, DEVLINK_CMD_SB_PORT_POOL_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	devlink_sb_port_pool_get_list_free(yds.first);
	return NULL;
}

/* ============== DEVLINK_CMD_SB_PORT_POOL_SET ============== */
/* DEVLINK_CMD_SB_PORT_POOL_SET - do */
void
devlink_sb_port_pool_set_req_free(struct devlink_sb_port_pool_set_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

int devlink_sb_port_pool_set(struct ynl_sock *ys,
			     struct devlink_sb_port_pool_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_SB_PORT_POOL_SET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);
	if (req->_present.sb_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_INDEX, req->sb_index);
	if (req->_present.sb_pool_index)
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_SB_POOL_INDEX, req->sb_pool_index);
	if (req->_present.sb_threshold)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_THRESHOLD, req->sb_threshold);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_SB_TC_POOL_BIND_GET ============== */
/* DEVLINK_CMD_SB_TC_POOL_BIND_GET - do */
void
devlink_sb_tc_pool_bind_get_req_free(struct devlink_sb_tc_pool_bind_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void
devlink_sb_tc_pool_bind_get_rsp_free(struct devlink_sb_tc_pool_bind_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp);
}

int devlink_sb_tc_pool_bind_get_rsp_parse(const struct nlmsghdr *nlh,
					  struct ynl_parse_arg *yarg)
{
	struct devlink_sb_tc_pool_bind_get_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.port_index = 1;
			dst->port_index = ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_SB_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sb_index = 1;
			dst->sb_index = ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_SB_POOL_TYPE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sb_pool_type = 1;
			dst->sb_pool_type = ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_SB_TC_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.sb_tc_index = 1;
			dst->sb_tc_index = ynl_attr_get_u16(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_sb_tc_pool_bind_get_rsp *
devlink_sb_tc_pool_bind_get(struct ynl_sock *ys,
			    struct devlink_sb_tc_pool_bind_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_sb_tc_pool_bind_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_SB_TC_POOL_BIND_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);
	if (req->_present.sb_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_INDEX, req->sb_index);
	if (req->_present.sb_pool_type)
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_SB_POOL_TYPE, req->sb_pool_type);
	if (req->_present.sb_tc_index)
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_SB_TC_INDEX, req->sb_tc_index);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_sb_tc_pool_bind_get_rsp_parse;
	yrs.rsp_cmd = 25;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_sb_tc_pool_bind_get_rsp_free(rsp);
	return NULL;
}

/* DEVLINK_CMD_SB_TC_POOL_BIND_GET - dump */
void
devlink_sb_tc_pool_bind_get_req_dump_free(struct devlink_sb_tc_pool_bind_get_req_dump *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void
devlink_sb_tc_pool_bind_get_list_free(struct devlink_sb_tc_pool_bind_get_list *rsp)
{
	struct devlink_sb_tc_pool_bind_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.bus_name);
		free(rsp->obj.dev_name);
		free(rsp);
	}
}

struct devlink_sb_tc_pool_bind_get_list *
devlink_sb_tc_pool_bind_get_dump(struct ynl_sock *ys,
				 struct devlink_sb_tc_pool_bind_get_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct devlink_sb_tc_pool_bind_get_list);
	yds.cb = devlink_sb_tc_pool_bind_get_rsp_parse;
	yds.rsp_cmd = 25;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, DEVLINK_CMD_SB_TC_POOL_BIND_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	devlink_sb_tc_pool_bind_get_list_free(yds.first);
	return NULL;
}

/* ============== DEVLINK_CMD_SB_TC_POOL_BIND_SET ============== */
/* DEVLINK_CMD_SB_TC_POOL_BIND_SET - do */
void
devlink_sb_tc_pool_bind_set_req_free(struct devlink_sb_tc_pool_bind_set_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

int devlink_sb_tc_pool_bind_set(struct ynl_sock *ys,
				struct devlink_sb_tc_pool_bind_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_SB_TC_POOL_BIND_SET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);
	if (req->_present.sb_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_INDEX, req->sb_index);
	if (req->_present.sb_pool_index)
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_SB_POOL_INDEX, req->sb_pool_index);
	if (req->_present.sb_pool_type)
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_SB_POOL_TYPE, req->sb_pool_type);
	if (req->_present.sb_tc_index)
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_SB_TC_INDEX, req->sb_tc_index);
	if (req->_present.sb_threshold)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_THRESHOLD, req->sb_threshold);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_SB_OCC_SNAPSHOT ============== */
/* DEVLINK_CMD_SB_OCC_SNAPSHOT - do */
void devlink_sb_occ_snapshot_req_free(struct devlink_sb_occ_snapshot_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

int devlink_sb_occ_snapshot(struct ynl_sock *ys,
			    struct devlink_sb_occ_snapshot_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_SB_OCC_SNAPSHOT, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.sb_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_INDEX, req->sb_index);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_SB_OCC_MAX_CLEAR ============== */
/* DEVLINK_CMD_SB_OCC_MAX_CLEAR - do */
void
devlink_sb_occ_max_clear_req_free(struct devlink_sb_occ_max_clear_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

int devlink_sb_occ_max_clear(struct ynl_sock *ys,
			     struct devlink_sb_occ_max_clear_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_SB_OCC_MAX_CLEAR, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.sb_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_SB_INDEX, req->sb_index);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_ESWITCH_GET ============== */
/* DEVLINK_CMD_ESWITCH_GET - do */
void devlink_eswitch_get_req_free(struct devlink_eswitch_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_eswitch_get_rsp_free(struct devlink_eswitch_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp);
}

int devlink_eswitch_get_rsp_parse(const struct nlmsghdr *nlh,
				  struct ynl_parse_arg *yarg)
{
	struct devlink_eswitch_get_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_ESWITCH_MODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.eswitch_mode = 1;
			dst->eswitch_mode = ynl_attr_get_u16(attr);
		} else if (type == DEVLINK_ATTR_ESWITCH_INLINE_MODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.eswitch_inline_mode = 1;
			dst->eswitch_inline_mode = ynl_attr_get_u8(attr);
		} else if (type == DEVLINK_ATTR_ESWITCH_ENCAP_MODE) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.eswitch_encap_mode = 1;
			dst->eswitch_encap_mode = ynl_attr_get_u8(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_eswitch_get_rsp *
devlink_eswitch_get(struct ynl_sock *ys, struct devlink_eswitch_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_eswitch_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_ESWITCH_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_eswitch_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_ESWITCH_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_eswitch_get_rsp_free(rsp);
	return NULL;
}

/* ============== DEVLINK_CMD_ESWITCH_SET ============== */
/* DEVLINK_CMD_ESWITCH_SET - do */
void devlink_eswitch_set_req_free(struct devlink_eswitch_set_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

int devlink_eswitch_set(struct ynl_sock *ys,
			struct devlink_eswitch_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_ESWITCH_SET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.eswitch_mode)
		ynl_attr_put_u16(nlh, DEVLINK_ATTR_ESWITCH_MODE, req->eswitch_mode);
	if (req->_present.eswitch_inline_mode)
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_ESWITCH_INLINE_MODE, req->eswitch_inline_mode);
	if (req->_present.eswitch_encap_mode)
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_ESWITCH_ENCAP_MODE, req->eswitch_encap_mode);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_DPIPE_TABLE_GET ============== */
/* DEVLINK_CMD_DPIPE_TABLE_GET - do */
void devlink_dpipe_table_get_req_free(struct devlink_dpipe_table_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->dpipe_table_name);
	free(req);
}

void devlink_dpipe_table_get_rsp_free(struct devlink_dpipe_table_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	devlink_dl_dpipe_tables_free(&rsp->dpipe_tables);
	free(rsp);
}

int devlink_dpipe_table_get_rsp_parse(const struct nlmsghdr *nlh,
				      struct ynl_parse_arg *yarg)
{
	struct devlink_dpipe_table_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;

	dst = yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DPIPE_TABLES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_tables = 1;

			parg.rsp_policy = &devlink_dl_dpipe_tables_nest;
			parg.data = &dst->dpipe_tables;
			if (devlink_dl_dpipe_tables_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_dpipe_table_get_rsp *
devlink_dpipe_table_get(struct ynl_sock *ys,
			struct devlink_dpipe_table_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_dpipe_table_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_DPIPE_TABLE_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_len.dpipe_table_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DPIPE_TABLE_NAME, req->dpipe_table_name);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_dpipe_table_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_DPIPE_TABLE_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_dpipe_table_get_rsp_free(rsp);
	return NULL;
}

/* ============== DEVLINK_CMD_DPIPE_ENTRIES_GET ============== */
/* DEVLINK_CMD_DPIPE_ENTRIES_GET - do */
void
devlink_dpipe_entries_get_req_free(struct devlink_dpipe_entries_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->dpipe_table_name);
	free(req);
}

void
devlink_dpipe_entries_get_rsp_free(struct devlink_dpipe_entries_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	devlink_dl_dpipe_entries_free(&rsp->dpipe_entries);
	free(rsp);
}

int devlink_dpipe_entries_get_rsp_parse(const struct nlmsghdr *nlh,
					struct ynl_parse_arg *yarg)
{
	struct devlink_dpipe_entries_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;

	dst = yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DPIPE_ENTRIES) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_entries = 1;

			parg.rsp_policy = &devlink_dl_dpipe_entries_nest;
			parg.data = &dst->dpipe_entries;
			if (devlink_dl_dpipe_entries_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_dpipe_entries_get_rsp *
devlink_dpipe_entries_get(struct ynl_sock *ys,
			  struct devlink_dpipe_entries_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_dpipe_entries_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_DPIPE_ENTRIES_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_len.dpipe_table_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DPIPE_TABLE_NAME, req->dpipe_table_name);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_dpipe_entries_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_DPIPE_ENTRIES_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_dpipe_entries_get_rsp_free(rsp);
	return NULL;
}

/* ============== DEVLINK_CMD_DPIPE_HEADERS_GET ============== */
/* DEVLINK_CMD_DPIPE_HEADERS_GET - do */
void
devlink_dpipe_headers_get_req_free(struct devlink_dpipe_headers_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void
devlink_dpipe_headers_get_rsp_free(struct devlink_dpipe_headers_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	devlink_dl_dpipe_headers_free(&rsp->dpipe_headers);
	free(rsp);
}

int devlink_dpipe_headers_get_rsp_parse(const struct nlmsghdr *nlh,
					struct ynl_parse_arg *yarg)
{
	struct devlink_dpipe_headers_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;

	dst = yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DPIPE_HEADERS) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.dpipe_headers = 1;

			parg.rsp_policy = &devlink_dl_dpipe_headers_nest;
			parg.data = &dst->dpipe_headers;
			if (devlink_dl_dpipe_headers_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_dpipe_headers_get_rsp *
devlink_dpipe_headers_get(struct ynl_sock *ys,
			  struct devlink_dpipe_headers_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_dpipe_headers_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_DPIPE_HEADERS_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_dpipe_headers_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_DPIPE_HEADERS_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_dpipe_headers_get_rsp_free(rsp);
	return NULL;
}

/* ============== DEVLINK_CMD_DPIPE_TABLE_COUNTERS_SET ============== */
/* DEVLINK_CMD_DPIPE_TABLE_COUNTERS_SET - do */
void
devlink_dpipe_table_counters_set_req_free(struct devlink_dpipe_table_counters_set_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->dpipe_table_name);
	free(req);
}

int devlink_dpipe_table_counters_set(struct ynl_sock *ys,
				     struct devlink_dpipe_table_counters_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_DPIPE_TABLE_COUNTERS_SET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_len.dpipe_table_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DPIPE_TABLE_NAME, req->dpipe_table_name);
	if (req->_present.dpipe_table_counters_enabled)
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED, req->dpipe_table_counters_enabled);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_RESOURCE_SET ============== */
/* DEVLINK_CMD_RESOURCE_SET - do */
void devlink_resource_set_req_free(struct devlink_resource_set_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

int devlink_resource_set(struct ynl_sock *ys,
			 struct devlink_resource_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_RESOURCE_SET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.resource_id)
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_RESOURCE_ID, req->resource_id);
	if (req->_present.resource_size)
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_RESOURCE_SIZE, req->resource_size);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_RESOURCE_DUMP ============== */
/* DEVLINK_CMD_RESOURCE_DUMP - do */
void devlink_resource_dump_req_free(struct devlink_resource_dump_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_resource_dump_rsp_free(struct devlink_resource_dump_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	devlink_dl_resource_list_free(&rsp->resource_list);
	free(rsp);
}

int devlink_resource_dump_rsp_parse(const struct nlmsghdr *nlh,
				    struct ynl_parse_arg *yarg)
{
	struct devlink_resource_dump_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;

	dst = yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_RESOURCE_LIST) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.resource_list = 1;

			parg.rsp_policy = &devlink_dl_resource_list_nest;
			parg.data = &dst->resource_list;
			if (devlink_dl_resource_list_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_resource_dump_rsp *
devlink_resource_dump(struct ynl_sock *ys,
		      struct devlink_resource_dump_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_resource_dump_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_RESOURCE_DUMP, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_resource_dump_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_RESOURCE_DUMP;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_resource_dump_rsp_free(rsp);
	return NULL;
}

/* ============== DEVLINK_CMD_RELOAD ============== */
/* DEVLINK_CMD_RELOAD - do */
void devlink_reload_req_free(struct devlink_reload_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_reload_rsp_free(struct devlink_reload_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp);
}

int devlink_reload_rsp_parse(const struct nlmsghdr *nlh,
			     struct ynl_parse_arg *yarg)
{
	struct devlink_reload_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_RELOAD_ACTIONS_PERFORMED) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.reload_actions_performed = 1;
			memcpy(&dst->reload_actions_performed, ynl_attr_data(attr), sizeof(struct nla_bitfield32));
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_reload_rsp *
devlink_reload(struct ynl_sock *ys, struct devlink_reload_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_reload_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_RELOAD, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.reload_action)
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_RELOAD_ACTION, req->reload_action);
	if (req->_present.reload_limits)
		ynl_attr_put(nlh, DEVLINK_ATTR_RELOAD_LIMITS, &req->reload_limits, sizeof(struct nla_bitfield32));
	if (req->_present.netns_pid)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_NETNS_PID, req->netns_pid);
	if (req->_present.netns_fd)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_NETNS_FD, req->netns_fd);
	if (req->_present.netns_id)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_NETNS_ID, req->netns_id);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_reload_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_RELOAD;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_reload_rsp_free(rsp);
	return NULL;
}

/* ============== DEVLINK_CMD_PARAM_GET ============== */
/* DEVLINK_CMD_PARAM_GET - do */
void devlink_param_get_req_free(struct devlink_param_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->param_name);
	free(req);
}

void devlink_param_get_rsp_free(struct devlink_param_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp->param_name);
	free(rsp);
}

int devlink_param_get_rsp_parse(const struct nlmsghdr *nlh,
				struct ynl_parse_arg *yarg)
{
	struct devlink_param_get_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_PARAM_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.param_name = len;
			dst->param_name = malloc(len + 1);
			memcpy(dst->param_name, ynl_attr_get_str(attr), len);
			dst->param_name[len] = 0;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_param_get_rsp *
devlink_param_get(struct ynl_sock *ys, struct devlink_param_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_param_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_PARAM_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_len.param_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_PARAM_NAME, req->param_name);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_param_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_PARAM_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_param_get_rsp_free(rsp);
	return NULL;
}

/* DEVLINK_CMD_PARAM_GET - dump */
void devlink_param_get_req_dump_free(struct devlink_param_get_req_dump *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_param_get_list_free(struct devlink_param_get_list *rsp)
{
	struct devlink_param_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.bus_name);
		free(rsp->obj.dev_name);
		free(rsp->obj.param_name);
		free(rsp);
	}
}

struct devlink_param_get_list *
devlink_param_get_dump(struct ynl_sock *ys,
		       struct devlink_param_get_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct devlink_param_get_list);
	yds.cb = devlink_param_get_rsp_parse;
	yds.rsp_cmd = DEVLINK_CMD_PARAM_GET;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, DEVLINK_CMD_PARAM_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	devlink_param_get_list_free(yds.first);
	return NULL;
}

/* ============== DEVLINK_CMD_PARAM_SET ============== */
/* DEVLINK_CMD_PARAM_SET - do */
void devlink_param_set_req_free(struct devlink_param_set_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->param_name);
	free(req);
}

int devlink_param_set(struct ynl_sock *ys, struct devlink_param_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_PARAM_SET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_len.param_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_PARAM_NAME, req->param_name);
	if (req->_present.param_type)
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_PARAM_TYPE, req->param_type);
	if (req->_present.param_value_cmode)
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_PARAM_VALUE_CMODE, req->param_value_cmode);
	if (req->_present.param_reset_default)
		ynl_attr_put(nlh, DEVLINK_ATTR_PARAM_RESET_DEFAULT, NULL, 0);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_REGION_GET ============== */
/* DEVLINK_CMD_REGION_GET - do */
void devlink_region_get_req_free(struct devlink_region_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->region_name);
	free(req);
}

void devlink_region_get_rsp_free(struct devlink_region_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp->region_name);
	free(rsp);
}

int devlink_region_get_rsp_parse(const struct nlmsghdr *nlh,
				 struct ynl_parse_arg *yarg)
{
	struct devlink_region_get_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.port_index = 1;
			dst->port_index = ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_REGION_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.region_name = len;
			dst->region_name = malloc(len + 1);
			memcpy(dst->region_name, ynl_attr_get_str(attr), len);
			dst->region_name[len] = 0;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_region_get_rsp *
devlink_region_get(struct ynl_sock *ys, struct devlink_region_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_region_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_REGION_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);
	if (req->_len.region_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_REGION_NAME, req->region_name);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_region_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_REGION_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_region_get_rsp_free(rsp);
	return NULL;
}

/* DEVLINK_CMD_REGION_GET - dump */
void devlink_region_get_req_dump_free(struct devlink_region_get_req_dump *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_region_get_list_free(struct devlink_region_get_list *rsp)
{
	struct devlink_region_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.bus_name);
		free(rsp->obj.dev_name);
		free(rsp->obj.region_name);
		free(rsp);
	}
}

struct devlink_region_get_list *
devlink_region_get_dump(struct ynl_sock *ys,
			struct devlink_region_get_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct devlink_region_get_list);
	yds.cb = devlink_region_get_rsp_parse;
	yds.rsp_cmd = DEVLINK_CMD_REGION_GET;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, DEVLINK_CMD_REGION_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	devlink_region_get_list_free(yds.first);
	return NULL;
}

/* ============== DEVLINK_CMD_REGION_NEW ============== */
/* DEVLINK_CMD_REGION_NEW - do */
void devlink_region_new_req_free(struct devlink_region_new_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->region_name);
	free(req);
}

void devlink_region_new_rsp_free(struct devlink_region_new_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp->region_name);
	free(rsp);
}

int devlink_region_new_rsp_parse(const struct nlmsghdr *nlh,
				 struct ynl_parse_arg *yarg)
{
	struct devlink_region_new_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.port_index = 1;
			dst->port_index = ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_REGION_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.region_name = len;
			dst->region_name = malloc(len + 1);
			memcpy(dst->region_name, ynl_attr_get_str(attr), len);
			dst->region_name[len] = 0;
		} else if (type == DEVLINK_ATTR_REGION_SNAPSHOT_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.region_snapshot_id = 1;
			dst->region_snapshot_id = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_region_new_rsp *
devlink_region_new(struct ynl_sock *ys, struct devlink_region_new_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_region_new_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_REGION_NEW, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);
	if (req->_len.region_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_REGION_NAME, req->region_name);
	if (req->_present.region_snapshot_id)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_REGION_SNAPSHOT_ID, req->region_snapshot_id);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_region_new_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_REGION_NEW;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_region_new_rsp_free(rsp);
	return NULL;
}

/* ============== DEVLINK_CMD_REGION_DEL ============== */
/* DEVLINK_CMD_REGION_DEL - do */
void devlink_region_del_req_free(struct devlink_region_del_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->region_name);
	free(req);
}

int devlink_region_del(struct ynl_sock *ys, struct devlink_region_del_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_REGION_DEL, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);
	if (req->_len.region_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_REGION_NAME, req->region_name);
	if (req->_present.region_snapshot_id)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_REGION_SNAPSHOT_ID, req->region_snapshot_id);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_REGION_READ ============== */
/* DEVLINK_CMD_REGION_READ - dump */
int devlink_region_read_rsp_parse(const struct nlmsghdr *nlh,
				  struct ynl_parse_arg *yarg)
{
	struct devlink_region_read_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.port_index = 1;
			dst->port_index = ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_REGION_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.region_name = len;
			dst->region_name = malloc(len + 1);
			memcpy(dst->region_name, ynl_attr_get_str(attr), len);
			dst->region_name[len] = 0;
		}
	}

	return YNL_PARSE_CB_OK;
}

void devlink_region_read_req_free(struct devlink_region_read_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->region_name);
	free(req);
}

void devlink_region_read_list_free(struct devlink_region_read_list *rsp)
{
	struct devlink_region_read_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.bus_name);
		free(rsp->obj.dev_name);
		free(rsp->obj.region_name);
		free(rsp);
	}
}

struct devlink_region_read_list *
devlink_region_read_dump(struct ynl_sock *ys,
			 struct devlink_region_read_req *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct devlink_region_read_list);
	yds.cb = devlink_region_read_rsp_parse;
	yds.rsp_cmd = DEVLINK_CMD_REGION_READ;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, DEVLINK_CMD_REGION_READ, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);
	if (req->_len.region_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_REGION_NAME, req->region_name);
	if (req->_present.region_snapshot_id)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_REGION_SNAPSHOT_ID, req->region_snapshot_id);
	if (req->_present.region_direct)
		ynl_attr_put(nlh, DEVLINK_ATTR_REGION_DIRECT, NULL, 0);
	if (req->_present.region_chunk_addr)
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_REGION_CHUNK_ADDR, req->region_chunk_addr);
	if (req->_present.region_chunk_len)
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_REGION_CHUNK_LEN, req->region_chunk_len);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	devlink_region_read_list_free(yds.first);
	return NULL;
}

/* ============== DEVLINK_CMD_PORT_PARAM_GET ============== */
/* DEVLINK_CMD_PORT_PARAM_GET - do */
void devlink_port_param_get_req_free(struct devlink_port_param_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_port_param_get_rsp_free(struct devlink_port_param_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp);
}

int devlink_port_param_get_rsp_parse(const struct nlmsghdr *nlh,
				     struct ynl_parse_arg *yarg)
{
	struct devlink_port_param_get_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.port_index = 1;
			dst->port_index = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_port_param_get_rsp *
devlink_port_param_get(struct ynl_sock *ys,
		       struct devlink_port_param_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_port_param_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_PORT_PARAM_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_port_param_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_PORT_PARAM_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_port_param_get_rsp_free(rsp);
	return NULL;
}

/* DEVLINK_CMD_PORT_PARAM_GET - dump */
void devlink_port_param_get_list_free(struct devlink_port_param_get_list *rsp)
{
	struct devlink_port_param_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.bus_name);
		free(rsp->obj.dev_name);
		free(rsp);
	}
}

struct devlink_port_param_get_list *
devlink_port_param_get_dump(struct ynl_sock *ys)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct devlink_port_param_get_list);
	yds.cb = devlink_port_param_get_rsp_parse;
	yds.rsp_cmd = DEVLINK_CMD_PORT_PARAM_GET;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, DEVLINK_CMD_PORT_PARAM_GET, 1);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	devlink_port_param_get_list_free(yds.first);
	return NULL;
}

/* ============== DEVLINK_CMD_PORT_PARAM_SET ============== */
/* DEVLINK_CMD_PORT_PARAM_SET - do */
void devlink_port_param_set_req_free(struct devlink_port_param_set_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

int devlink_port_param_set(struct ynl_sock *ys,
			   struct devlink_port_param_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_PORT_PARAM_SET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_INFO_GET ============== */
/* DEVLINK_CMD_INFO_GET - do */
void devlink_info_get_req_free(struct devlink_info_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_info_get_rsp_free(struct devlink_info_get_rsp *rsp)
{
	unsigned int i;

	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp->info_driver_name);
	free(rsp->info_serial_number);
	for (i = 0; i < rsp->_count.info_version_fixed; i++)
		devlink_dl_info_version_free(&rsp->info_version_fixed[i]);
	free(rsp->info_version_fixed);
	for (i = 0; i < rsp->_count.info_version_running; i++)
		devlink_dl_info_version_free(&rsp->info_version_running[i]);
	free(rsp->info_version_running);
	for (i = 0; i < rsp->_count.info_version_stored; i++)
		devlink_dl_info_version_free(&rsp->info_version_stored[i]);
	free(rsp->info_version_stored);
	free(rsp->info_board_serial_number);
	free(rsp);
}

int devlink_info_get_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	unsigned int n_info_version_running = 0;
	unsigned int n_info_version_stored = 0;
	unsigned int n_info_version_fixed = 0;
	struct devlink_info_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;
	unsigned int len;
	int i;

	dst = yarg->data;
	parg.ys = yarg->ys;

	if (dst->info_version_fixed)
		return ynl_error_parse(yarg, "attribute already present (devlink.info-version-fixed)");
	if (dst->info_version_running)
		return ynl_error_parse(yarg, "attribute already present (devlink.info-version-running)");
	if (dst->info_version_stored)
		return ynl_error_parse(yarg, "attribute already present (devlink.info-version-stored)");

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_INFO_DRIVER_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.info_driver_name = len;
			dst->info_driver_name = malloc(len + 1);
			memcpy(dst->info_driver_name, ynl_attr_get_str(attr), len);
			dst->info_driver_name[len] = 0;
		} else if (type == DEVLINK_ATTR_INFO_SERIAL_NUMBER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.info_serial_number = len;
			dst->info_serial_number = malloc(len + 1);
			memcpy(dst->info_serial_number, ynl_attr_get_str(attr), len);
			dst->info_serial_number[len] = 0;
		} else if (type == DEVLINK_ATTR_INFO_VERSION_FIXED) {
			n_info_version_fixed++;
		} else if (type == DEVLINK_ATTR_INFO_VERSION_RUNNING) {
			n_info_version_running++;
		} else if (type == DEVLINK_ATTR_INFO_VERSION_STORED) {
			n_info_version_stored++;
		} else if (type == DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.info_board_serial_number = len;
			dst->info_board_serial_number = malloc(len + 1);
			memcpy(dst->info_board_serial_number, ynl_attr_get_str(attr), len);
			dst->info_board_serial_number[len] = 0;
		}
	}

	if (n_info_version_fixed) {
		dst->info_version_fixed = calloc(n_info_version_fixed, sizeof(*dst->info_version_fixed));
		dst->_count.info_version_fixed = n_info_version_fixed;
		i = 0;
		parg.rsp_policy = &devlink_dl_info_version_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_INFO_VERSION_FIXED) {
				parg.data = &dst->info_version_fixed[i];
				if (devlink_dl_info_version_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}
	if (n_info_version_running) {
		dst->info_version_running = calloc(n_info_version_running, sizeof(*dst->info_version_running));
		dst->_count.info_version_running = n_info_version_running;
		i = 0;
		parg.rsp_policy = &devlink_dl_info_version_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_INFO_VERSION_RUNNING) {
				parg.data = &dst->info_version_running[i];
				if (devlink_dl_info_version_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}
	if (n_info_version_stored) {
		dst->info_version_stored = calloc(n_info_version_stored, sizeof(*dst->info_version_stored));
		dst->_count.info_version_stored = n_info_version_stored;
		i = 0;
		parg.rsp_policy = &devlink_dl_info_version_nest;
		ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
			if (ynl_attr_type(attr) == DEVLINK_ATTR_INFO_VERSION_STORED) {
				parg.data = &dst->info_version_stored[i];
				if (devlink_dl_info_version_parse(&parg, attr))
					return YNL_PARSE_CB_ERROR;
				i++;
			}
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_info_get_rsp *
devlink_info_get(struct ynl_sock *ys, struct devlink_info_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_info_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_INFO_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_info_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_INFO_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_info_get_rsp_free(rsp);
	return NULL;
}

/* DEVLINK_CMD_INFO_GET - dump */
void devlink_info_get_list_free(struct devlink_info_get_list *rsp)
{
	struct devlink_info_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		unsigned int i;

		rsp = next;
		next = rsp->next;

		free(rsp->obj.bus_name);
		free(rsp->obj.dev_name);
		free(rsp->obj.info_driver_name);
		free(rsp->obj.info_serial_number);
		for (i = 0; i < rsp->obj._count.info_version_fixed; i++)
			devlink_dl_info_version_free(&rsp->obj.info_version_fixed[i]);
		free(rsp->obj.info_version_fixed);
		for (i = 0; i < rsp->obj._count.info_version_running; i++)
			devlink_dl_info_version_free(&rsp->obj.info_version_running[i]);
		free(rsp->obj.info_version_running);
		for (i = 0; i < rsp->obj._count.info_version_stored; i++)
			devlink_dl_info_version_free(&rsp->obj.info_version_stored[i]);
		free(rsp->obj.info_version_stored);
		free(rsp->obj.info_board_serial_number);
		free(rsp);
	}
}

struct devlink_info_get_list *devlink_info_get_dump(struct ynl_sock *ys)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct devlink_info_get_list);
	yds.cb = devlink_info_get_rsp_parse;
	yds.rsp_cmd = DEVLINK_CMD_INFO_GET;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, DEVLINK_CMD_INFO_GET, 1);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	devlink_info_get_list_free(yds.first);
	return NULL;
}

/* ============== DEVLINK_CMD_HEALTH_REPORTER_GET ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_GET - do */
void
devlink_health_reporter_get_req_free(struct devlink_health_reporter_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->health_reporter_name);
	free(req);
}

void
devlink_health_reporter_get_rsp_free(struct devlink_health_reporter_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp->health_reporter_name);
	free(rsp);
}

int devlink_health_reporter_get_rsp_parse(const struct nlmsghdr *nlh,
					  struct ynl_parse_arg *yarg)
{
	struct devlink_health_reporter_get_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.port_index = 1;
			dst->port_index = ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_HEALTH_REPORTER_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.health_reporter_name = len;
			dst->health_reporter_name = malloc(len + 1);
			memcpy(dst->health_reporter_name, ynl_attr_get_str(attr), len);
			dst->health_reporter_name[len] = 0;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_health_reporter_get_rsp *
devlink_health_reporter_get(struct ynl_sock *ys,
			    struct devlink_health_reporter_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_health_reporter_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_HEALTH_REPORTER_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);
	if (req->_len.health_reporter_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_HEALTH_REPORTER_NAME, req->health_reporter_name);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_health_reporter_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_HEALTH_REPORTER_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_health_reporter_get_rsp_free(rsp);
	return NULL;
}

/* DEVLINK_CMD_HEALTH_REPORTER_GET - dump */
void
devlink_health_reporter_get_req_dump_free(struct devlink_health_reporter_get_req_dump *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void
devlink_health_reporter_get_list_free(struct devlink_health_reporter_get_list *rsp)
{
	struct devlink_health_reporter_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.bus_name);
		free(rsp->obj.dev_name);
		free(rsp->obj.health_reporter_name);
		free(rsp);
	}
}

struct devlink_health_reporter_get_list *
devlink_health_reporter_get_dump(struct ynl_sock *ys,
				 struct devlink_health_reporter_get_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct devlink_health_reporter_get_list);
	yds.cb = devlink_health_reporter_get_rsp_parse;
	yds.rsp_cmd = DEVLINK_CMD_HEALTH_REPORTER_GET;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, DEVLINK_CMD_HEALTH_REPORTER_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	devlink_health_reporter_get_list_free(yds.first);
	return NULL;
}

/* ============== DEVLINK_CMD_HEALTH_REPORTER_SET ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_SET - do */
void
devlink_health_reporter_set_req_free(struct devlink_health_reporter_set_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->health_reporter_name);
	free(req);
}

int devlink_health_reporter_set(struct ynl_sock *ys,
				struct devlink_health_reporter_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_HEALTH_REPORTER_SET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);
	if (req->_len.health_reporter_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_HEALTH_REPORTER_NAME, req->health_reporter_name);
	if (req->_present.health_reporter_graceful_period)
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD, req->health_reporter_graceful_period);
	if (req->_present.health_reporter_auto_recover)
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER, req->health_reporter_auto_recover);
	if (req->_present.health_reporter_auto_dump)
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP, req->health_reporter_auto_dump);
	if (req->_present.health_reporter_burst_period)
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_HEALTH_REPORTER_BURST_PERIOD, req->health_reporter_burst_period);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_HEALTH_REPORTER_RECOVER ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_RECOVER - do */
void
devlink_health_reporter_recover_req_free(struct devlink_health_reporter_recover_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->health_reporter_name);
	free(req);
}

int devlink_health_reporter_recover(struct ynl_sock *ys,
				    struct devlink_health_reporter_recover_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_HEALTH_REPORTER_RECOVER, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);
	if (req->_len.health_reporter_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_HEALTH_REPORTER_NAME, req->health_reporter_name);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_HEALTH_REPORTER_DIAGNOSE ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_DIAGNOSE - do */
void
devlink_health_reporter_diagnose_req_free(struct devlink_health_reporter_diagnose_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->health_reporter_name);
	free(req);
}

int devlink_health_reporter_diagnose(struct ynl_sock *ys,
				     struct devlink_health_reporter_diagnose_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_HEALTH_REPORTER_DIAGNOSE, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);
	if (req->_len.health_reporter_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_HEALTH_REPORTER_NAME, req->health_reporter_name);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET - dump */
int devlink_health_reporter_dump_get_rsp_parse(const struct nlmsghdr *nlh,
					       struct ynl_parse_arg *yarg)
{
	struct devlink_health_reporter_dump_get_rsp *dst;
	const struct nlattr *attr;
	struct ynl_parse_arg parg;

	dst = yarg->data;
	parg.ys = yarg->ys;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_FMSG) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.fmsg = 1;

			parg.rsp_policy = &devlink_dl_fmsg_nest;
			parg.data = &dst->fmsg;
			if (devlink_dl_fmsg_parse(&parg, attr))
				return YNL_PARSE_CB_ERROR;
		}
	}

	return YNL_PARSE_CB_OK;
}

void
devlink_health_reporter_dump_get_req_free(struct devlink_health_reporter_dump_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->health_reporter_name);
	free(req);
}

void
devlink_health_reporter_dump_get_list_free(struct devlink_health_reporter_dump_get_list *rsp)
{
	struct devlink_health_reporter_dump_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		devlink_dl_fmsg_free(&rsp->obj.fmsg);
		free(rsp);
	}
}

struct devlink_health_reporter_dump_get_list *
devlink_health_reporter_dump_get_dump(struct ynl_sock *ys,
				      struct devlink_health_reporter_dump_get_req *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct devlink_health_reporter_dump_get_list);
	yds.cb = devlink_health_reporter_dump_get_rsp_parse;
	yds.rsp_cmd = DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);
	if (req->_len.health_reporter_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_HEALTH_REPORTER_NAME, req->health_reporter_name);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	devlink_health_reporter_dump_get_list_free(yds.first);
	return NULL;
}

/* ============== DEVLINK_CMD_HEALTH_REPORTER_DUMP_CLEAR ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_DUMP_CLEAR - do */
void
devlink_health_reporter_dump_clear_req_free(struct devlink_health_reporter_dump_clear_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->health_reporter_name);
	free(req);
}

int devlink_health_reporter_dump_clear(struct ynl_sock *ys,
				       struct devlink_health_reporter_dump_clear_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_HEALTH_REPORTER_DUMP_CLEAR, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);
	if (req->_len.health_reporter_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_HEALTH_REPORTER_NAME, req->health_reporter_name);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_FLASH_UPDATE ============== */
/* DEVLINK_CMD_FLASH_UPDATE - do */
void devlink_flash_update_req_free(struct devlink_flash_update_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->flash_update_file_name);
	free(req->flash_update_component);
	free(req);
}

int devlink_flash_update(struct ynl_sock *ys,
			 struct devlink_flash_update_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_FLASH_UPDATE, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_len.flash_update_file_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME, req->flash_update_file_name);
	if (req->_len.flash_update_component)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_FLASH_UPDATE_COMPONENT, req->flash_update_component);
	if (req->_present.flash_update_overwrite_mask)
		ynl_attr_put(nlh, DEVLINK_ATTR_FLASH_UPDATE_OVERWRITE_MASK, &req->flash_update_overwrite_mask, sizeof(struct nla_bitfield32));

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_TRAP_GET ============== */
/* DEVLINK_CMD_TRAP_GET - do */
void devlink_trap_get_req_free(struct devlink_trap_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->trap_name);
	free(req);
}

void devlink_trap_get_rsp_free(struct devlink_trap_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp->trap_name);
	free(rsp);
}

int devlink_trap_get_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	struct devlink_trap_get_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_TRAP_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.trap_name = len;
			dst->trap_name = malloc(len + 1);
			memcpy(dst->trap_name, ynl_attr_get_str(attr), len);
			dst->trap_name[len] = 0;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_trap_get_rsp *
devlink_trap_get(struct ynl_sock *ys, struct devlink_trap_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_trap_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_TRAP_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_len.trap_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_TRAP_NAME, req->trap_name);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_trap_get_rsp_parse;
	yrs.rsp_cmd = 63;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_trap_get_rsp_free(rsp);
	return NULL;
}

/* DEVLINK_CMD_TRAP_GET - dump */
void devlink_trap_get_req_dump_free(struct devlink_trap_get_req_dump *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_trap_get_list_free(struct devlink_trap_get_list *rsp)
{
	struct devlink_trap_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.bus_name);
		free(rsp->obj.dev_name);
		free(rsp->obj.trap_name);
		free(rsp);
	}
}

struct devlink_trap_get_list *
devlink_trap_get_dump(struct ynl_sock *ys,
		      struct devlink_trap_get_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct devlink_trap_get_list);
	yds.cb = devlink_trap_get_rsp_parse;
	yds.rsp_cmd = 63;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, DEVLINK_CMD_TRAP_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	devlink_trap_get_list_free(yds.first);
	return NULL;
}

/* ============== DEVLINK_CMD_TRAP_SET ============== */
/* DEVLINK_CMD_TRAP_SET - do */
void devlink_trap_set_req_free(struct devlink_trap_set_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->trap_name);
	free(req);
}

int devlink_trap_set(struct ynl_sock *ys, struct devlink_trap_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_TRAP_SET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_len.trap_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_TRAP_NAME, req->trap_name);
	if (req->_present.trap_action)
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_TRAP_ACTION, req->trap_action);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_TRAP_GROUP_GET ============== */
/* DEVLINK_CMD_TRAP_GROUP_GET - do */
void devlink_trap_group_get_req_free(struct devlink_trap_group_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->trap_group_name);
	free(req);
}

void devlink_trap_group_get_rsp_free(struct devlink_trap_group_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp->trap_group_name);
	free(rsp);
}

int devlink_trap_group_get_rsp_parse(const struct nlmsghdr *nlh,
				     struct ynl_parse_arg *yarg)
{
	struct devlink_trap_group_get_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_TRAP_GROUP_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.trap_group_name = len;
			dst->trap_group_name = malloc(len + 1);
			memcpy(dst->trap_group_name, ynl_attr_get_str(attr), len);
			dst->trap_group_name[len] = 0;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_trap_group_get_rsp *
devlink_trap_group_get(struct ynl_sock *ys,
		       struct devlink_trap_group_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_trap_group_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_TRAP_GROUP_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_len.trap_group_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_TRAP_GROUP_NAME, req->trap_group_name);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_trap_group_get_rsp_parse;
	yrs.rsp_cmd = 67;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_trap_group_get_rsp_free(rsp);
	return NULL;
}

/* DEVLINK_CMD_TRAP_GROUP_GET - dump */
void
devlink_trap_group_get_req_dump_free(struct devlink_trap_group_get_req_dump *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_trap_group_get_list_free(struct devlink_trap_group_get_list *rsp)
{
	struct devlink_trap_group_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.bus_name);
		free(rsp->obj.dev_name);
		free(rsp->obj.trap_group_name);
		free(rsp);
	}
}

struct devlink_trap_group_get_list *
devlink_trap_group_get_dump(struct ynl_sock *ys,
			    struct devlink_trap_group_get_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct devlink_trap_group_get_list);
	yds.cb = devlink_trap_group_get_rsp_parse;
	yds.rsp_cmd = 67;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, DEVLINK_CMD_TRAP_GROUP_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	devlink_trap_group_get_list_free(yds.first);
	return NULL;
}

/* ============== DEVLINK_CMD_TRAP_GROUP_SET ============== */
/* DEVLINK_CMD_TRAP_GROUP_SET - do */
void devlink_trap_group_set_req_free(struct devlink_trap_group_set_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->trap_group_name);
	free(req);
}

int devlink_trap_group_set(struct ynl_sock *ys,
			   struct devlink_trap_group_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_TRAP_GROUP_SET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_len.trap_group_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_TRAP_GROUP_NAME, req->trap_group_name);
	if (req->_present.trap_action)
		ynl_attr_put_u8(nlh, DEVLINK_ATTR_TRAP_ACTION, req->trap_action);
	if (req->_present.trap_policer_id)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_TRAP_POLICER_ID, req->trap_policer_id);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_TRAP_POLICER_GET ============== */
/* DEVLINK_CMD_TRAP_POLICER_GET - do */
void
devlink_trap_policer_get_req_free(struct devlink_trap_policer_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void
devlink_trap_policer_get_rsp_free(struct devlink_trap_policer_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp);
}

int devlink_trap_policer_get_rsp_parse(const struct nlmsghdr *nlh,
				       struct ynl_parse_arg *yarg)
{
	struct devlink_trap_policer_get_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_TRAP_POLICER_ID) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.trap_policer_id = 1;
			dst->trap_policer_id = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_trap_policer_get_rsp *
devlink_trap_policer_get(struct ynl_sock *ys,
			 struct devlink_trap_policer_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_trap_policer_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_TRAP_POLICER_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.trap_policer_id)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_TRAP_POLICER_ID, req->trap_policer_id);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_trap_policer_get_rsp_parse;
	yrs.rsp_cmd = 71;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_trap_policer_get_rsp_free(rsp);
	return NULL;
}

/* DEVLINK_CMD_TRAP_POLICER_GET - dump */
void
devlink_trap_policer_get_req_dump_free(struct devlink_trap_policer_get_req_dump *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void
devlink_trap_policer_get_list_free(struct devlink_trap_policer_get_list *rsp)
{
	struct devlink_trap_policer_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.bus_name);
		free(rsp->obj.dev_name);
		free(rsp);
	}
}

struct devlink_trap_policer_get_list *
devlink_trap_policer_get_dump(struct ynl_sock *ys,
			      struct devlink_trap_policer_get_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct devlink_trap_policer_get_list);
	yds.cb = devlink_trap_policer_get_rsp_parse;
	yds.rsp_cmd = 71;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, DEVLINK_CMD_TRAP_POLICER_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	devlink_trap_policer_get_list_free(yds.first);
	return NULL;
}

/* ============== DEVLINK_CMD_TRAP_POLICER_SET ============== */
/* DEVLINK_CMD_TRAP_POLICER_SET - do */
void
devlink_trap_policer_set_req_free(struct devlink_trap_policer_set_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

int devlink_trap_policer_set(struct ynl_sock *ys,
			     struct devlink_trap_policer_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_TRAP_POLICER_SET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.trap_policer_id)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_TRAP_POLICER_ID, req->trap_policer_id);
	if (req->_present.trap_policer_rate)
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_TRAP_POLICER_RATE, req->trap_policer_rate);
	if (req->_present.trap_policer_burst)
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_TRAP_POLICER_BURST, req->trap_policer_burst);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_HEALTH_REPORTER_TEST ============== */
/* DEVLINK_CMD_HEALTH_REPORTER_TEST - do */
void
devlink_health_reporter_test_req_free(struct devlink_health_reporter_test_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->health_reporter_name);
	free(req);
}

int devlink_health_reporter_test(struct ynl_sock *ys,
				 struct devlink_health_reporter_test_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_HEALTH_REPORTER_TEST, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);
	if (req->_len.health_reporter_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_HEALTH_REPORTER_NAME, req->health_reporter_name);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_RATE_GET ============== */
/* DEVLINK_CMD_RATE_GET - do */
void devlink_rate_get_req_free(struct devlink_rate_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->rate_node_name);
	free(req);
}

void devlink_rate_get_rsp_free(struct devlink_rate_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp->rate_node_name);
	free(rsp);
}

int devlink_rate_get_rsp_parse(const struct nlmsghdr *nlh,
			       struct ynl_parse_arg *yarg)
{
	struct devlink_rate_get_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_PORT_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.port_index = 1;
			dst->port_index = ynl_attr_get_u32(attr);
		} else if (type == DEVLINK_ATTR_RATE_NODE_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.rate_node_name = len;
			dst->rate_node_name = malloc(len + 1);
			memcpy(dst->rate_node_name, ynl_attr_get_str(attr), len);
			dst->rate_node_name[len] = 0;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_rate_get_rsp *
devlink_rate_get(struct ynl_sock *ys, struct devlink_rate_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_rate_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_RATE_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);
	if (req->_len.rate_node_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_RATE_NODE_NAME, req->rate_node_name);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_rate_get_rsp_parse;
	yrs.rsp_cmd = 76;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_rate_get_rsp_free(rsp);
	return NULL;
}

/* DEVLINK_CMD_RATE_GET - dump */
void devlink_rate_get_req_dump_free(struct devlink_rate_get_req_dump *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_rate_get_list_free(struct devlink_rate_get_list *rsp)
{
	struct devlink_rate_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.bus_name);
		free(rsp->obj.dev_name);
		free(rsp->obj.rate_node_name);
		free(rsp);
	}
}

struct devlink_rate_get_list *
devlink_rate_get_dump(struct ynl_sock *ys,
		      struct devlink_rate_get_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct devlink_rate_get_list);
	yds.cb = devlink_rate_get_rsp_parse;
	yds.rsp_cmd = 76;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, DEVLINK_CMD_RATE_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	devlink_rate_get_list_free(yds.first);
	return NULL;
}

/* ============== DEVLINK_CMD_RATE_SET ============== */
/* DEVLINK_CMD_RATE_SET - do */
void devlink_rate_set_req_free(struct devlink_rate_set_req *req)
{
	unsigned int i;

	free(req->bus_name);
	free(req->dev_name);
	free(req->rate_node_name);
	free(req->rate_parent_node_name);
	for (i = 0; i < req->_count.rate_tc_bws; i++)
		devlink_dl_rate_tc_bws_free(&req->rate_tc_bws[i]);
	free(req->rate_tc_bws);
	free(req);
}

int devlink_rate_set(struct ynl_sock *ys, struct devlink_rate_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	unsigned int i;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_RATE_SET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_len.rate_node_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_RATE_NODE_NAME, req->rate_node_name);
	if (req->_present.rate_tx_share)
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_RATE_TX_SHARE, req->rate_tx_share);
	if (req->_present.rate_tx_max)
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_RATE_TX_MAX, req->rate_tx_max);
	if (req->_present.rate_tx_priority)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_RATE_TX_PRIORITY, req->rate_tx_priority);
	if (req->_present.rate_tx_weight)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_RATE_TX_WEIGHT, req->rate_tx_weight);
	if (req->_len.rate_parent_node_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_RATE_PARENT_NODE_NAME, req->rate_parent_node_name);
	for (i = 0; i < req->_count.rate_tc_bws; i++)
		devlink_dl_rate_tc_bws_put(nlh, DEVLINK_ATTR_RATE_TC_BWS, &req->rate_tc_bws[i]);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_RATE_NEW ============== */
/* DEVLINK_CMD_RATE_NEW - do */
void devlink_rate_new_req_free(struct devlink_rate_new_req *req)
{
	unsigned int i;

	free(req->bus_name);
	free(req->dev_name);
	free(req->rate_node_name);
	free(req->rate_parent_node_name);
	for (i = 0; i < req->_count.rate_tc_bws; i++)
		devlink_dl_rate_tc_bws_free(&req->rate_tc_bws[i]);
	free(req->rate_tc_bws);
	free(req);
}

int devlink_rate_new(struct ynl_sock *ys, struct devlink_rate_new_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	unsigned int i;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_RATE_NEW, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_len.rate_node_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_RATE_NODE_NAME, req->rate_node_name);
	if (req->_present.rate_tx_share)
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_RATE_TX_SHARE, req->rate_tx_share);
	if (req->_present.rate_tx_max)
		ynl_attr_put_u64(nlh, DEVLINK_ATTR_RATE_TX_MAX, req->rate_tx_max);
	if (req->_present.rate_tx_priority)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_RATE_TX_PRIORITY, req->rate_tx_priority);
	if (req->_present.rate_tx_weight)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_RATE_TX_WEIGHT, req->rate_tx_weight);
	if (req->_len.rate_parent_node_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_RATE_PARENT_NODE_NAME, req->rate_parent_node_name);
	for (i = 0; i < req->_count.rate_tc_bws; i++)
		devlink_dl_rate_tc_bws_put(nlh, DEVLINK_ATTR_RATE_TC_BWS, &req->rate_tc_bws[i]);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_RATE_DEL ============== */
/* DEVLINK_CMD_RATE_DEL - do */
void devlink_rate_del_req_free(struct devlink_rate_del_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->rate_node_name);
	free(req);
}

int devlink_rate_del(struct ynl_sock *ys, struct devlink_rate_del_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_RATE_DEL, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_len.rate_node_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_RATE_NODE_NAME, req->rate_node_name);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_LINECARD_GET ============== */
/* DEVLINK_CMD_LINECARD_GET - do */
void devlink_linecard_get_req_free(struct devlink_linecard_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_linecard_get_rsp_free(struct devlink_linecard_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp);
}

int devlink_linecard_get_rsp_parse(const struct nlmsghdr *nlh,
				   struct ynl_parse_arg *yarg)
{
	struct devlink_linecard_get_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		} else if (type == DEVLINK_ATTR_LINECARD_INDEX) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;
			dst->_present.linecard_index = 1;
			dst->linecard_index = ynl_attr_get_u32(attr);
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_linecard_get_rsp *
devlink_linecard_get(struct ynl_sock *ys, struct devlink_linecard_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_linecard_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_LINECARD_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.linecard_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_LINECARD_INDEX, req->linecard_index);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_linecard_get_rsp_parse;
	yrs.rsp_cmd = 80;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_linecard_get_rsp_free(rsp);
	return NULL;
}

/* DEVLINK_CMD_LINECARD_GET - dump */
void
devlink_linecard_get_req_dump_free(struct devlink_linecard_get_req_dump *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_linecard_get_list_free(struct devlink_linecard_get_list *rsp)
{
	struct devlink_linecard_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.bus_name);
		free(rsp->obj.dev_name);
		free(rsp);
	}
}

struct devlink_linecard_get_list *
devlink_linecard_get_dump(struct ynl_sock *ys,
			  struct devlink_linecard_get_req_dump *req)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct devlink_linecard_get_list);
	yds.cb = devlink_linecard_get_rsp_parse;
	yds.rsp_cmd = 80;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, DEVLINK_CMD_LINECARD_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	devlink_linecard_get_list_free(yds.first);
	return NULL;
}

/* ============== DEVLINK_CMD_LINECARD_SET ============== */
/* DEVLINK_CMD_LINECARD_SET - do */
void devlink_linecard_set_req_free(struct devlink_linecard_set_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req->linecard_type);
	free(req);
}

int devlink_linecard_set(struct ynl_sock *ys,
			 struct devlink_linecard_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_LINECARD_SET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.linecard_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_LINECARD_INDEX, req->linecard_index);
	if (req->_len.linecard_type)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_LINECARD_TYPE, req->linecard_type);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_SELFTESTS_GET ============== */
/* DEVLINK_CMD_SELFTESTS_GET - do */
void devlink_selftests_get_req_free(struct devlink_selftests_get_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

void devlink_selftests_get_rsp_free(struct devlink_selftests_get_rsp *rsp)
{
	free(rsp->bus_name);
	free(rsp->dev_name);
	free(rsp);
}

int devlink_selftests_get_rsp_parse(const struct nlmsghdr *nlh,
				    struct ynl_parse_arg *yarg)
{
	struct devlink_selftests_get_rsp *dst;
	const struct nlattr *attr;
	unsigned int len;

	dst = yarg->data;

	ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len) {
		unsigned int type = ynl_attr_type(attr);

		if (type == DEVLINK_ATTR_BUS_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.bus_name = len;
			dst->bus_name = malloc(len + 1);
			memcpy(dst->bus_name, ynl_attr_get_str(attr), len);
			dst->bus_name[len] = 0;
		} else if (type == DEVLINK_ATTR_DEV_NAME) {
			if (ynl_attr_validate(yarg, attr))
				return YNL_PARSE_CB_ERROR;

			len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));
			dst->_len.dev_name = len;
			dst->dev_name = malloc(len + 1);
			memcpy(dst->dev_name, ynl_attr_get_str(attr), len);
			dst->dev_name[len] = 0;
		}
	}

	return YNL_PARSE_CB_OK;
}

struct devlink_selftests_get_rsp *
devlink_selftests_get(struct ynl_sock *ys,
		      struct devlink_selftests_get_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct devlink_selftests_get_rsp *rsp;
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_SELFTESTS_GET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;
	yrs.yarg.rsp_policy = &devlink_nest;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);

	rsp = calloc(1, sizeof(*rsp));
	yrs.yarg.data = rsp;
	yrs.cb = devlink_selftests_get_rsp_parse;
	yrs.rsp_cmd = DEVLINK_CMD_SELFTESTS_GET;

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		goto err_free;

	return rsp;

err_free:
	devlink_selftests_get_rsp_free(rsp);
	return NULL;
}

/* DEVLINK_CMD_SELFTESTS_GET - dump */
void devlink_selftests_get_list_free(struct devlink_selftests_get_list *rsp)
{
	struct devlink_selftests_get_list *next = rsp;

	while ((void *)next != YNL_LIST_END) {
		rsp = next;
		next = rsp->next;

		free(rsp->obj.bus_name);
		free(rsp->obj.dev_name);
		free(rsp);
	}
}

struct devlink_selftests_get_list *
devlink_selftests_get_dump(struct ynl_sock *ys)
{
	struct ynl_dump_state yds = {};
	struct nlmsghdr *nlh;
	int err;

	yds.yarg.ys = ys;
	yds.yarg.rsp_policy = &devlink_nest;
	yds.yarg.data = NULL;
	yds.alloc_sz = sizeof(struct devlink_selftests_get_list);
	yds.cb = devlink_selftests_get_rsp_parse;
	yds.rsp_cmd = DEVLINK_CMD_SELFTESTS_GET;

	nlh = ynl_gemsg_start_dump(ys, ys->family_id, DEVLINK_CMD_SELFTESTS_GET, 1);

	err = ynl_exec_dump(ys, nlh, &yds);
	if (err < 0)
		goto free_list;

	return yds.first;

free_list:
	devlink_selftests_get_list_free(yds.first);
	return NULL;
}

/* ============== DEVLINK_CMD_SELFTESTS_RUN ============== */
/* DEVLINK_CMD_SELFTESTS_RUN - do */
void devlink_selftests_run_req_free(struct devlink_selftests_run_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	devlink_dl_selftest_id_free(&req->selftests);
	free(req);
}

int devlink_selftests_run(struct ynl_sock *ys,
			  struct devlink_selftests_run_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_SELFTESTS_RUN, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.selftests)
		devlink_dl_selftest_id_put(nlh, DEVLINK_ATTR_SELFTESTS, &req->selftests);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

/* ============== DEVLINK_CMD_NOTIFY_FILTER_SET ============== */
/* DEVLINK_CMD_NOTIFY_FILTER_SET - do */
void
devlink_notify_filter_set_req_free(struct devlink_notify_filter_set_req *req)
{
	free(req->bus_name);
	free(req->dev_name);
	free(req);
}

int devlink_notify_filter_set(struct ynl_sock *ys,
			      struct devlink_notify_filter_set_req *req)
{
	struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };
	struct nlmsghdr *nlh;
	int err;

	nlh = ynl_gemsg_start_req(ys, ys->family_id, DEVLINK_CMD_NOTIFY_FILTER_SET, 1);
	ys->req_policy = &devlink_nest;
	ys->req_hdr_len = ys->family->hdr_len;

	if (req->_len.bus_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_BUS_NAME, req->bus_name);
	if (req->_len.dev_name)
		ynl_attr_put_str(nlh, DEVLINK_ATTR_DEV_NAME, req->dev_name);
	if (req->_present.port_index)
		ynl_attr_put_u32(nlh, DEVLINK_ATTR_PORT_INDEX, req->port_index);

	err = ynl_exec(ys, nlh, &yrs);
	if (err < 0)
		return -1;

	return 0;
}

const struct ynl_family ynl_devlink_family =  {
	.name		= "devlink",
	.hdr_len	= sizeof(struct genlmsghdr),
};
