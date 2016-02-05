/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "saiinternal.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_nhop.h"

static int api_log_level[SAI_API_MAX];
static char log_buffer[SAI_LOG_BUFFER_SIZE + 1];
static sai_api_service_t sai_api_service;
static sai_api_t api_id = SAI_API_UNSPECIFIED;
switch_device_t device = 0;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static const char *module[] = {
    "UNSPECIFIED",
    "SWITCH",
    "PORT",
    "FDB",
    "VLAN",
    "VIRTUAL_ROUTER",
    "ROUTE",
    "NEXT_HOP",
    "NEXT_HOP_GROUP",
    "ROUTER_INTERFACE",
    "NEIGHBOR",
    "ACL",
    "HOST_INTERFACE",
    "MIRROR",
    "SAMPLEPACKET",
    "STP",
    "LAG",
    "POLICER",
    "WRED",
    "QOS_MAPS",
    "QUEUE",
    "SCHEDULER",
    "SCHEDULER_GROUP",
    "BUFFERS",
    "HASH",
    "UDF",
    "IPMC",
    "L2MC",
};

sai_status_t sai_api_query(
        _In_ sai_api_t sai_api_id,
        _Out_ void ** api_method_table)
{
    sai_status_t status =  SAI_STATUS_SUCCESS;

    SAI_LOG_ENTER();

    if (!api_method_table) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null api method table: %s",
                      sai_status_to_string(status));
        return status;
    }

    switch (sai_api_id) {
        case SAI_API_SWITCH:
            *api_method_table = &sai_api_service.switch_api;
            break;

        case SAI_API_PORT:
            *api_method_table = &sai_api_service.port_api;
            break;

        case SAI_API_FDB:
            *api_method_table = &sai_api_service.fdb_api;
            break;

        case SAI_API_VLAN:
            *api_method_table = &sai_api_service.vlan_api;
            break;

        case SAI_API_VIRTUAL_ROUTER:
            *api_method_table = &sai_api_service.vr_api;
            break;

        case SAI_API_ROUTER_INTERFACE:
            *api_method_table = &sai_api_service.rif_api;
            break;

        case SAI_API_ROUTE:
            *api_method_table = &sai_api_service.route_api;
            break;

        case SAI_API_NEIGHBOR:
            *api_method_table = &sai_api_service.neighbor_api;
            break;

        case SAI_API_NEXT_HOP:
            *api_method_table = &sai_api_service.nhop_api;
            break;

        case SAI_API_NEXT_HOP_GROUP:
            *api_method_table = &sai_api_service.nhop_group_api;
            break;

        case SAI_API_QOS_MAPS:
            *api_method_table = &sai_api_service.qos_api;
            break;

        case SAI_API_ACL:
            *api_method_table = &sai_api_service.acl_api;
            break;

        case SAI_API_LAG:
            *api_method_table = &sai_api_service.lag_api;
            break;

        case SAI_API_STP:
            *api_method_table = &sai_api_service.stp_api;
            break;

        case SAI_API_HOST_INTERFACE:
            *api_method_table = &sai_api_service.hostif_api;
            break;

        case SAI_API_MIRROR:
            *api_method_table = &sai_api_service.mirror_api;
            break;

        case SAI_API_SAMPLEPACKET:
            *api_method_table = &sai_api_service.samplepacket_api;
            break;

        case SAI_API_IPMC:
            *api_method_table = &sai_api_service.ipmc_api;
            break;

        case SAI_API_L2MC:
            *api_method_table = &sai_api_service.l2mc_api;
            break;

        case SAI_API_POLICER:
            *api_method_table = &sai_api_service.policer_api;
            break;

        default:
            *api_method_table = NULL;
            status = SAI_STATUS_INVALID_PARAMETER;
    }

    if (status == SAI_STATUS_SUCCESS) {
        SAI_LOG_INFO("api query for module: %s", module[sai_api_id]);
    } else {
        SAI_LOG_ERROR("api query failed. invalid api id");
    }

    SAI_LOG_EXIT();

    return status;
}

/*
* Routine Description:
*     Query sai object type.
*
* Arguments:
*     [in] sai_object_id_t
*
* Return Values:
*    Return SAI_OBJECT_TYPE_NULL when sai_object_id is not valid.
*    Otherwise, return a valid sai object type SAI_OBJECT_TYPE_XXX
*/
sai_object_type_t
sai_object_type_query(
    _In_ sai_object_id_t sai_object_id) {

    SAI_LOG_ENTER();

    sai_object_type_t object_type = SAI_OBJECT_TYPE_NULL;
    switch_nhop_index_type_t nhop_type = 0;
    switch_handle_type_t handle_type = SWITCH_HANDLE_TYPE_NONE;

    handle_type = switch_handle_get_type(sai_object_id);
    switch (handle_type) {
        case SWITCH_HANDLE_TYPE_PORT:
            object_type = SAI_OBJECT_TYPE_PORT;
            break;
        case SWITCH_HANDLE_TYPE_LAG:
            object_type = SAI_OBJECT_TYPE_LAG;
            break;
        case SWITCH_HANDLE_TYPE_LAG_MEMBER:
            object_type = SAI_OBJECT_TYPE_LAG_MEMBER;
            break;
        case SWITCH_HANDLE_TYPE_INTERFACE:
            object_type = SAI_OBJECT_TYPE_ROUTER_INTERFACE;
            break;
        case SWITCH_HANDLE_TYPE_VRF:
            object_type = SAI_OBJECT_TYPE_VIRTUAL_ROUTER;
            break;
        case SWITCH_HANDLE_TYPE_NHOP:
            nhop_type = switch_api_nhop_type_get(sai_object_id);
            if (nhop_type == SWITCH_NHOP_INDEX_TYPE_ONE_PATH) {
                object_type = SAI_OBJECT_TYPE_NEXT_HOP;
            } else if (nhop_type == SWITCH_NHOP_INDEX_TYPE_ECMP) {
                object_type = SAI_OBJECT_TYPE_NEXT_HOP_GROUP;
            } else {
                object_type = SAI_OBJECT_TYPE_NULL;
            }
            break;
        case SWITCH_HANDLE_TYPE_STP:
            object_type = SAI_OBJECT_TYPE_STP_INSTANCE;
            break;
        case SWITCH_HANDLE_TYPE_ACL:
            object_type = SAI_OBJECT_TYPE_ACL_TABLE;
            break;
        case SWITCH_HANDLE_TYPE_ACE:
            object_type = SAI_OBJECT_TYPE_ACL_ENTRY;
            break;
        case SWITCH_HANDLE_TYPE_HOSTIF:
            object_type = SAI_OBJECT_TYPE_HOST_INTERFACE;
            break;
        case SWITCH_HANDLE_TYPE_HOSTIF_GROUP:
            object_type = SAI_OBJECT_TYPE_TRAP_GROUP;
            break;
        case SWITCH_HANDLE_TYPE_MIRROR:
            object_type = SAI_OBJECT_TYPE_MIRROR;
            break;
        case SWITCH_HANDLE_TYPE_MGID:
            object_type = SAI_OBJECT_TYPE_NEXT_HOP_GROUP;
            break;
        case SWITCH_HANDLE_TYPE_ACL_COUNTER:
            object_type = SAI_OBJECT_TYPE_ACL_COUNTER;
            break;
        case SWITCH_HANDLE_TYPE_METER:
            object_type = SAI_OBJECT_TYPE_POLICER;
            break;
        default:
            object_type = SAI_OBJECT_TYPE_NULL;
            break;
    }

    SAI_LOG_INFO("object type query: %lx : %s",
                 sai_object_id,
                 sai_object_type_to_string(object_type));

    SAI_LOG_EXIT();

    return object_type;
}

sai_status_t sai_initialize() {

    sai_api_t api = 0;

    for (api = 0; api < SAI_API_MAX; api++) {
        sai_log_set(api, SAI_LOG_CRITICAL);
    }

    SAI_LOG_ENTER();

    sai_switch_initialize(&sai_api_service);
    sai_port_initialize(&sai_api_service);
    sai_fdb_initialize(&sai_api_service);
    sai_vlan_initialize(&sai_api_service);
    sai_lag_initialize(&sai_api_service);
    sai_router_interface_initialize(&sai_api_service);
    sai_next_hop_initialize(&sai_api_service);
    sai_next_hop_group_initialize(&sai_api_service);
    sai_route_initialize(&sai_api_service);
    sai_virtual_router_initialize(&sai_api_service);
    sai_stp_initialize(&sai_api_service);
    sai_neighbor_initialize(&sai_api_service);
    sai_hostif_initialize(&sai_api_service);
    sai_acl_initialize(&sai_api_service);
    sai_mirror_initialize(&sai_api_service);
    sai_policer_initialize(&sai_api_service);
    sai_ipmc_initialize(&sai_api_service);
    sai_l2mc_initialize(&sai_api_service);

    SAI_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
}

sai_status_t sai_log_set(
    _In_ sai_api_t sai_api_id,
    _In_ sai_log_level_t log_level) {
    sai_status_t status =  SAI_STATUS_SUCCESS;
    api_log_level[sai_api_id] = log_level;
    return status;
}

void sai_log(int level, sai_api_t api, char *fmt, ...)
{
    va_list args;
    // compare if level of each API here?
    if(level < api_log_level[api]) {
        return;
    }
    va_start(args, fmt);
    vsnprintf(log_buffer, SAI_LOG_BUFFER_SIZE, fmt, args);
    va_end(args);
#if 1
    printf("%s: %s\n", module[api], log_buffer);
#else
    syslog(LOG_DEBUG-level, "%s: %s", module[api], log_buffer);
#endif
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
