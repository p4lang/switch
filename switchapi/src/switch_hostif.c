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

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_status.h"
#include "switchapi/switch_hostif.h"
#include "switchapi/switch_nhop.h"
#include "switch_pd.h"
#include "switch_log.h"
#include "switch_hostif_int.h"
#include "switch_packet_int.h"
#include "switch_nhop_int.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static void *switch_hostif_group_array;
static void *switch_hostif_rcode_array;
static void *switch_hostif_array;
static switch_hostif_rx_callback_fn rx_packet;
bool rx_callback_set = FALSE;
switch_hostif_nhop_t hostif_nhop[SWITCH_HOSTIF_REASON_CODE_MAX];

switch_status_t
switch_hostif_init(switch_device_t device)
{
    switch_hostif_rcode_info_t           *rcode_info = NULL;
    switch_api_hostif_rcode_info_t       *rcode_api_info = NULL;
    void                                 *temp = NULL;
    switch_handle_t                    mirror_handle;
    switch_api_mirror_info_t           api_mirror_info;

    switch_hostif_group_array = NULL;
    switch_hostif_rcode_array = NULL;
    switch_hostif_array = NULL;
    switch_handle_type_init(SWITCH_HANDLE_TYPE_HOSTIF_GROUP, (1024));
    switch_handle_type_init(SWITCH_HANDLE_TYPE_HOSTIF, (1024));
    rcode_info = switch_malloc(sizeof(switch_hostif_rcode_info_t), 1);
    if (!rcode_info) {
        return SWITCH_STATUS_NO_MEMORY;
    }
    rcode_api_info = &rcode_info->rcode_api_info;
    JLI(temp, switch_hostif_rcode_array, SWITCH_HOSTIF_REASON_CODE_NONE);
    rcode_api_info->reason_code = SWITCH_HOSTIF_REASON_CODE_NONE;
    *(unsigned long *)temp = (unsigned long) (rcode_info);

    switch_api_cpu_interface_create(device);

    // CPU port mirroring session
    memset(&api_mirror_info, 0, sizeof(switch_api_mirror_info_t));
    api_mirror_info.session_id = SWITCH_CPU_MIRROR_SESSION_ID;
    api_mirror_info.egress_port = CPU_PORT_ID;
    api_mirror_info.direction = SWITCH_API_DIRECTION_BOTH;
    api_mirror_info.session_type = SWITCH_MIRROR_SESSION_TYPE_SIMPLE;
    api_mirror_info.mirror_type = SWITCH_MIRROR_TYPE_LOCAL;
    mirror_handle = switch_api_mirror_session_create(device, &api_mirror_info);
    (void) mirror_handle;
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_hostif_free(switch_device_t device)
{
    switch_handle_type_free(SWITCH_HANDLE_TYPE_HOSTIF_GROUP);
    switch_handle_type_free(SWITCH_HANDLE_TYPE_HOSTIF);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_hostif_group_create()
{
    switch_handle_t hostif_group_handle;
    _switch_handle_create(SWITCH_HANDLE_TYPE_HOSTIF_GROUP, switch_hostif_group_t,
                          switch_hostif_group_array, NULL, hostif_group_handle);
    return hostif_group_handle;
}

switch_hostif_group_t *
switch_hostif_group_get(switch_handle_t hostif_group_handle)
{
    switch_hostif_group_t *hostif_group = NULL;
    _switch_handle_get(switch_hostif_group_t, switch_hostif_group_array, hostif_group_handle, hostif_group);
    return hostif_group;
}

switch_status_t
switch_hostif_group_delete(switch_handle_t handle)
{
    _switch_handle_delete(switch_hostif_group_t, switch_hostif_group_array, handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_api_hostif_group_create(switch_device_t device, switch_hostif_group_t *hostif_group)
{
    switch_handle_t                    hostif_group_handle = 0;
    switch_hostif_group_t             *hostif_group_temp = NULL;

    hostif_group_handle = switch_hostif_group_create();
    hostif_group_temp = switch_hostif_group_get(hostif_group_handle);
    if (!hostif_group_temp) {
        return SWITCH_API_INVALID_HANDLE;
    }
    memcpy(hostif_group_temp, hostif_group, sizeof(switch_hostif_group_t));
    return hostif_group_handle;
}

switch_status_t
switch_api_hostif_group_delete(switch_device_t device, switch_handle_t hostif_group_handle)
{
    switch_hostif_group_t *hostif_group = NULL;

    if (!SWITCH_HOSTIF_GROUP_HANDLE_VALID(hostif_group_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }
    hostif_group = switch_hostif_group_get(hostif_group_handle);
    if (!hostif_group) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }
    switch_hostif_group_delete(hostif_group_handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_hostif_reason_code_create(switch_device_t device, switch_api_hostif_rcode_info_t *rcode_api_info)
{
    switch_hostif_rcode_info_t           *rcode_info = NULL;
    void                                 *temp = NULL;
    switch_acl_system_key_value_pair_t    acl_kvp[SWITCH_ACL_SYSTEM_FIELD_MAX];
    switch_acl_action_t                   acl_action;
    switch_acl_action_params_t            action_params;
    switch_handle_t                       acl_handle = 0;
    int                                   priority;
    int                                   field_count = 0;
    switch_status_t                       status = SWITCH_STATUS_SUCCESS;
    switch_handle_t                       ace_handle;

    JLG(temp, switch_hostif_rcode_array, rcode_api_info->reason_code);
    if (!temp) {
        rcode_info = switch_malloc(sizeof(switch_hostif_rcode_info_t), 1);
        if (!rcode_info) {
            return SWITCH_STATUS_NO_MEMORY;
        }
        JLI(temp, switch_hostif_rcode_array, rcode_api_info->reason_code);
        *(unsigned long *)temp = (unsigned long) (rcode_info);
    }
    rcode_info = (switch_hostif_rcode_info_t *) (*(unsigned long *)temp);
    memcpy(&rcode_info->rcode_api_info, rcode_api_info, sizeof(switch_api_hostif_rcode_info_t));
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(&acl_kvp, 0, sizeof(switch_acl_system_key_value_pair_t));
    priority = rcode_api_info->priority;
    switch (rcode_api_info->reason_code) {
        case SWITCH_HOSTIF_REASON_CODE_STP:
            // stp bpdu, redirect to cpu
            acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_DEST_MAC;
            acl_kvp[0].value.dest_mac.mac_addr[0] = 0x01;
            acl_kvp[0].value.dest_mac.mac_addr[1] = 0x80;
            acl_kvp[0].value.dest_mac.mac_addr[2] = 0xC2;
            acl_kvp[0].value.dest_mac.mac_addr[3] = 0x00;
            acl_kvp[0].value.dest_mac.mac_addr[4] = 0x00;
            acl_kvp[0].value.dest_mac.mac_addr[5] = 0x00;
            acl_kvp[0].mask.u.mask = 0xFFFFFFFFFFFF;
            acl_action = rcode_api_info->action;
            field_count = 1;
            action_params.cpu_redirect.reason_code = rcode_api_info->reason_code;
            switch_api_acl_rule_create(device, acl_handle, 
                               priority, field_count,
                               acl_kvp, acl_action,
                               &action_params, &ace_handle);
            break;
        case SWITCH_HOSTIF_REASON_CODE_LACP:
            // lacp bpdu, redirect to cpu
            acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_DEST_MAC;
            acl_kvp[0].value.dest_mac.mac_addr[0] = 0x01;
            acl_kvp[0].value.dest_mac.mac_addr[1] = 0x80;
            acl_kvp[0].value.dest_mac.mac_addr[2] = 0xC2;
            acl_kvp[0].value.dest_mac.mac_addr[3] = 0x00;
            acl_kvp[0].value.dest_mac.mac_addr[4] = 0x00;
            acl_kvp[0].value.dest_mac.mac_addr[5] = 0x02;
            acl_kvp[0].mask.u.mask = 0xFFFFFFFFFFFF;
            acl_action = rcode_api_info->action;
            field_count = 1;
            action_params.cpu_redirect.reason_code = rcode_api_info->reason_code;
            switch_api_acl_rule_create(device, acl_handle, 
                               priority, field_count,
                               acl_kvp, acl_action,
                               &action_params, &ace_handle);
            break;
        case SWITCH_HOSTIF_REASON_CODE_LLDP:
            // lacp frame, redirect to cpu
            acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_DEST_MAC;
            acl_kvp[0].value.dest_mac.mac_addr[0] = 0x01;
            acl_kvp[0].value.dest_mac.mac_addr[1] = 0x80;
            acl_kvp[0].value.dest_mac.mac_addr[2] = 0xC2;
            acl_kvp[0].value.dest_mac.mac_addr[3] = 0x00;
            acl_kvp[0].value.dest_mac.mac_addr[4] = 0x00;
            acl_kvp[0].value.dest_mac.mac_addr[5] = 0x0e;
            acl_kvp[0].mask.u.mask = 0xFFFFFFFFFFFF;
            acl_kvp[1].field = SWITCH_ACL_SYSTEM_FIELD_ETH_TYPE;
            acl_kvp[1].value.eth_type = 0x88CC;
            acl_kvp[1].mask.u.mask = 0xFFFF;
            acl_action = rcode_api_info->action;
            field_count = 2;
            action_params.cpu_redirect.reason_code = rcode_api_info->reason_code;
            switch_api_acl_rule_create(device, acl_handle, 
                               priority, field_count,
                               acl_kvp, acl_action,
                               &action_params, &ace_handle);
            acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_DEST_MAC;
            acl_kvp[0].value.dest_mac.mac_addr[0] = 0x01;
            acl_kvp[0].value.dest_mac.mac_addr[1] = 0x80;
            acl_kvp[0].value.dest_mac.mac_addr[2] = 0xC2;
            acl_kvp[0].value.dest_mac.mac_addr[3] = 0x00;
            acl_kvp[0].value.dest_mac.mac_addr[4] = 0x00;
            acl_kvp[0].value.dest_mac.mac_addr[5] = 0x03;
            acl_kvp[0].mask.u.mask = 0xFFFFFFFFFFFF;
            acl_kvp[1].field = SWITCH_ACL_SYSTEM_FIELD_ETH_TYPE;
            acl_kvp[1].value.eth_type = 0x88CC;
            acl_kvp[1].mask.u.mask = 0xFFFF;
            acl_action = rcode_api_info->action;
            field_count = 2;
            action_params.cpu_redirect.reason_code = rcode_api_info->reason_code;
            priority++;
            switch_api_acl_rule_create(device, acl_handle, 
                               priority, field_count,
                               acl_kvp, acl_action,
                               &action_params, &ace_handle);
            acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_DEST_MAC;
            acl_kvp[0].value.dest_mac.mac_addr[0] = 0x01;
            acl_kvp[0].value.dest_mac.mac_addr[1] = 0x80;
            acl_kvp[0].value.dest_mac.mac_addr[2] = 0xC2;
            acl_kvp[0].value.dest_mac.mac_addr[3] = 0x00;
            acl_kvp[0].value.dest_mac.mac_addr[4] = 0x00;
            acl_kvp[0].value.dest_mac.mac_addr[5] = 0x00;
            acl_kvp[0].mask.u.mask = 0xFFFFFFFFFFFF;
            acl_kvp[1].field = SWITCH_ACL_SYSTEM_FIELD_ETH_TYPE;
            acl_kvp[1].value.eth_type = 0x88CC;
            acl_kvp[1].mask.u.mask = 0xFFFF;
            acl_action = rcode_api_info->action;
            field_count = 2;
            action_params.cpu_redirect.reason_code = rcode_api_info->reason_code;
            priority++;
            switch_api_acl_rule_create(device, acl_handle, 
                               priority, field_count,
                               acl_kvp, acl_action,
                               &action_params, &ace_handle);
            break;
        case SWITCH_HOSTIF_REASON_CODE_OSPF:
            // All OSPF routers 224.0.0.5, copy to cpu
            acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_IPV4_DEST;
            acl_kvp[0].value.ipv4_dest = 0xE0000005;
            acl_kvp[0].mask.u.mask = 0xFFFFFFFF;
            acl_kvp[1].field = SWITCH_ACL_SYSTEM_FIELD_IP_PROTO;
            acl_kvp[1].value.ip_proto = 89;
            acl_kvp[1].mask.u.mask = 0xFFFF;
            acl_action = rcode_api_info->action;
            field_count = 2;
            action_params.cpu_redirect.reason_code = rcode_api_info->reason_code;
            switch_api_acl_rule_create(device, acl_handle, 
                               priority, field_count,
                               acl_kvp, acl_action,
                               &action_params, &ace_handle);
            // All OSPF designated routes (DRs) 224.0.0.6, copy to cpu
            acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_IPV4_DEST;
            acl_kvp[0].value.ipv4_dest = 0xE0000006;
            acl_kvp[0].mask.u.mask = 0xFFFFFFFF;
            acl_kvp[1].field = SWITCH_ACL_SYSTEM_FIELD_IP_PROTO;
            acl_kvp[1].value.ip_proto = 89;
            acl_kvp[1].mask.u.mask = 0xFFFF;
            acl_action = rcode_api_info->action;
            field_count = 2;
            action_params.cpu_redirect.reason_code = rcode_api_info->reason_code;
            switch_api_acl_rule_create(device, acl_handle, 
                               priority + 1, field_count,
                               acl_kvp, acl_action,
                               &action_params, &ace_handle);
            break;
        case SWITCH_HOSTIF_REASON_CODE_PIM:
            // PIM packet, copy to cpu
            acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_IP_PROTO;
            acl_kvp[0].value.ip_proto = 103; 
            acl_kvp[0].mask.u.mask = 0xFFFF;
            acl_action = rcode_api_info->action;
            field_count = 1;
            action_params.cpu_redirect.reason_code = rcode_api_info->reason_code;
            switch_api_acl_rule_create(device, acl_handle, 
                               priority, field_count,
                               acl_kvp, acl_action,
                               &action_params, &ace_handle);
            break;
        case SWITCH_HOSTIF_REASON_CODE_ARP_REQUEST:
            acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_ETH_TYPE;
            acl_kvp[0].value.eth_type = 0x806;
            acl_kvp[0].mask.u.mask = 0xFFFF;
            acl_kvp[1].field = SWITCH_ACL_SYSTEM_FIELD_DEST_MAC;
            acl_kvp[1].value.dest_mac.mac_addr[0] = 0xFF;
            acl_kvp[1].value.dest_mac.mac_addr[1] = 0xFF;
            acl_kvp[1].value.dest_mac.mac_addr[2] = 0xFF;
            acl_kvp[1].value.dest_mac.mac_addr[3] = 0xFF;
            acl_kvp[1].value.dest_mac.mac_addr[4] = 0xFf;
            acl_kvp[1].value.dest_mac.mac_addr[5] = 0xFF;
            acl_kvp[1].mask.u.mask = 0xFFFFFFFFFFFF;
            acl_action = rcode_api_info->action;
            field_count = 2;
            action_params.cpu_redirect.reason_code = rcode_api_info->reason_code;
            switch_api_acl_rule_create(device, acl_handle, 
                               priority, field_count,
                               acl_kvp, acl_action,
                               &action_params, &ace_handle);
            break;
        case SWITCH_HOSTIF_REASON_CODE_ARP_RESPONSE:
            acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_ETH_TYPE;
            acl_kvp[0].value.eth_type = 0x806;
            acl_kvp[0].mask.u.mask = 0xFFFF;
            acl_kvp[1].field = SWITCH_ACL_SYSTEM_FIELD_RMAC_HIT;
            acl_kvp[1].value.rmac_hit = 1;
            acl_kvp[1].mask.u.mask = 0xFF;
            acl_action = rcode_api_info->action;
            field_count = 2;
            action_params.cpu_redirect.reason_code = rcode_api_info->reason_code;
            switch_api_acl_rule_create(device, acl_handle, 
                               priority, field_count,
                               acl_kvp, acl_action,
                               &action_params, &ace_handle);
            break;
        case SWITCH_HOSTIF_REASON_CODE_TTL_ERROR:
            acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_TTL;
            acl_kvp[0].value.ttl = 0x0;
            acl_kvp[0].mask.u.mask = 0xFF;
            acl_kvp[1].field = SWITCH_ACL_SYSTEM_FIELD_ROUTED;
            acl_kvp[1].value.routed = 1;
            acl_kvp[1].mask.u.mask = 0xFF;
            acl_action = rcode_api_info->action;
            field_count = 2;
            action_params.cpu_redirect.reason_code = rcode_api_info->reason_code;
            switch_api_acl_rule_create(device, acl_handle, 
                               priority, field_count,
                               acl_kvp, acl_action,
                               &action_params, &ace_handle);

            acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_TTL;
            acl_kvp[0].value.ttl = 0x1;
            acl_kvp[0].mask.u.mask = 0xFF;
            acl_kvp[1].field = SWITCH_ACL_SYSTEM_FIELD_ROUTED;
            acl_kvp[1].value.routed = 1;
            acl_kvp[1].mask.u.mask = 0xFF;
            acl_action = rcode_api_info->action;
            field_count = 2;
            action_params.cpu_redirect.reason_code = rcode_api_info->reason_code;
            switch_api_acl_rule_create(device, acl_handle, 
                               priority, field_count,
                               acl_kvp, acl_action,
                               &action_params, &ace_handle);
            break;
        default:
            status = SWITCH_STATUS_NOT_SUPPORTED;
            break;
    }
    return status;
}

switch_status_t
switch_api_hostif_reason_code_update(switch_device_t device, switch_api_hostif_rcode_info_t *rcode_api_info)
{
    switch_hostif_rcode_info_t        *rcode_info = NULL;
    void                              *temp = NULL;
    switch_api_hostif_rcode_info_t    *rcode_api_info_temp = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    bool                               action_set = FALSE;
    int                                priority = 1000;

    JLG(temp, switch_hostif_rcode_array, rcode_api_info->reason_code);
    if (!temp) {
        rcode_info = switch_malloc(sizeof(switch_hostif_rcode_info_t), 1);
        if (!rcode_info) {
            return SWITCH_STATUS_NO_MEMORY;
        }
        memset(rcode_info, 0, sizeof(switch_hostif_rcode_info_t));
        JLI(temp, switch_hostif_rcode_array, rcode_api_info->reason_code);
        *(unsigned long *)temp = (unsigned long) (rcode_info);
        rcode_info->rcode_api_info.reason_code = rcode_api_info->reason_code;
    }
    rcode_info = (switch_hostif_rcode_info_t *) (*(unsigned long *)temp);
    rcode_api_info_temp = &rcode_info->rcode_api_info;

    if (rcode_api_info->action) {
        rcode_api_info_temp->action = rcode_api_info->action;
        action_set = TRUE;
    }

    if (rcode_api_info->priority) {
        rcode_api_info_temp->priority = rcode_api_info->priority;
    } else {
        rcode_api_info_temp->priority = priority;
    }

    if (rcode_api_info->channel) {
        rcode_api_info_temp->channel = rcode_api_info->channel;
    }

    if (rcode_api_info->hostif_group_id) {
        rcode_api_info_temp->hostif_group_id = rcode_api_info->hostif_group_id;
    }

    if (action_set) {
        status = switch_api_hostif_reason_code_create(device, rcode_api_info_temp);
    }
    return status;
}

switch_status_t
switch_api_hostif_reason_code_delete(switch_device_t device, switch_hostif_reason_code_t reason_code)
{
    switch_hostif_rcode_info_t        *rcode_info = NULL;
    switch_api_hostif_rcode_info_t    *rcode_api_info = NULL;
    void                              *temp = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    int                                priority_shift = 8;
    int                                priority = 0;

    JLG(temp, switch_hostif_rcode_array, reason_code);
    if (!temp) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    rcode_info = (switch_hostif_rcode_info_t *) (*(unsigned long *)temp);
    rcode_api_info = &rcode_info->rcode_api_info;
    priority = rcode_api_info->priority << priority_shift;
    switch (rcode_api_info->reason_code) {
        case SWITCH_HOSTIF_REASON_CODE_STP:
            status = switch_api_acl_rule_delete(device, rcode_info->acl_handle, priority);
            status = switch_api_acl_remove(device, rcode_info->acl_handle, 0);
            break;
        case SWITCH_HOSTIF_REASON_CODE_LACP:
            status = switch_api_acl_rule_delete(device, rcode_info->acl_handle, priority);
            status = switch_api_acl_remove(device, rcode_info->acl_handle, 0);
            break;
        case SWITCH_HOSTIF_REASON_CODE_LLDP:
            status = switch_api_acl_rule_delete(device, rcode_info->acl_handle, priority);
            priority++;
            status = switch_api_acl_rule_delete(device, rcode_info->acl_handle, priority);
            priority++;
            status = switch_api_acl_rule_delete(device, rcode_info->acl_handle, priority);
            status = switch_api_acl_remove(device, rcode_info->acl_handle, 0);
            break;
        case SWITCH_HOSTIF_REASON_CODE_OSPF:
            status = switch_api_acl_rule_delete(device, rcode_info->acl_handle, priority);
            priority++;
            status = switch_api_acl_rule_delete(device, rcode_info->acl_handle, priority);
            status = switch_api_acl_remove(device, rcode_info->acl_handle, 0);
            break;
        case SWITCH_HOSTIF_REASON_CODE_PIM:
            status = switch_api_acl_rule_delete(device, rcode_info->acl_handle, priority);
            status = switch_api_acl_remove(device, rcode_info->acl_handle, 0);
            break;
        default:
            status = SWITCH_STATUS_NOT_SUPPORTED;
            break;
    }
    return status;
}

switch_status_t
switch_api_hostif_register_rx_callback(switch_device_t device, switch_hostif_rx_callback_fn cb_fn)
{
    rx_packet = cb_fn;
    rx_callback_set = TRUE;
    return SWITCH_STATUS_SUCCESS;
}


switch_status_t
switch_api_hostif_deregister_rx_callback(switch_device_t device, switch_hostif_rx_callback_fn cb_fn)
{
    rx_callback_set = FALSE;
    return SWITCH_STATUS_SUCCESS;
}

const char *
switch_api_hostif_code_string(switch_hostif_reason_code_t reason_code)
{
    switch (reason_code) {
        case SWITCH_HOSTIF_REASON_CODE_STP:
            return "stp";
        case SWITCH_HOSTIF_REASON_CODE_LACP:
            return "lacp";
        case SWITCH_HOSTIF_REASON_CODE_LLDP:
            return "lldp";
        case SWITCH_HOSTIF_REASON_CODE_OSPF:
            return "ospf";
        case SWITCH_HOSTIF_REASON_CODE_PIM:
            return "pim";
        default:
            return "unknown";
    }
}

switch_status_t
switch_api_hostif_rx_packet_from_hw(switch_packet_header_t *packet_header, char *packet, int packet_size)
{
    switch_cpu_header_t               *cpu_header = NULL;
    switch_hostif_rcode_info_t        *rcode_info = NULL;
    switch_interface_info_t           *intf_info = NULL;
    void                              *temp = NULL;
    switch_hostif_packet_t             hostif_packet;
    switch_handle_t                    intf_handle = 0;
    switch_handle_t                    hostif_handle = 0;
    switch_hostif_info_t              *hostif_info = NULL;
    switch_handle_t                    port_handle = 0;
    switch_port_info_t                *port_info = NULL;

    memset(&hostif_packet, 0, sizeof(switch_hostif_packet_t));
    cpu_header = &packet_header->cpu_header;

    JLG(temp, switch_hostif_rcode_array, cpu_header->reason_code);
    if (!temp) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    SWITCH_API_TRACE("Received packet with %s trap on ifindex %x\n",
                     switch_api_hostif_code_string(cpu_header->reason_code),
                     cpu_header->ingress_ifindex);

    rcode_info = (switch_hostif_rcode_info_t *) (*(unsigned long *)temp);
    if ((rcode_info->rcode_api_info.reason_code == SWITCH_HOSTIF_REASON_CODE_NONE) ||
        (rcode_info->rcode_api_info.channel == SWITCH_HOSTIF_CHANNEL_CB)) {
        hostif_packet.reason_code = cpu_header->reason_code;
        hostif_packet.pkt = packet;
        hostif_packet.pkt_size = packet_size;

        intf_handle = switch_api_interface_get_from_ifindex(cpu_header->ingress_ifindex);
        intf_info = switch_api_interface_get(intf_handle);
        if (!intf_info) {
            return SWITCH_STATUS_INVALID_INTERFACE;
        }
        hostif_packet.handle = intf_info->api_intf_info.u.port_lag_handle;
        if (SWITCH_IS_LAG_IFINDEX(cpu_header->ingress_ifindex)) {
            hostif_packet.is_lag = TRUE;
        }
        if (rx_callback_set) {
            SWITCH_API_TRACE("Sending packet through cb\n");
            rx_packet(&hostif_packet);
        }
    }
    if ((rcode_info->rcode_api_info.reason_code == SWITCH_HOSTIF_REASON_CODE_NONE) ||
       (rcode_info->rcode_api_info.channel == SWITCH_HOSTIF_CHANNEL_NETDEV)) {
        intf_handle = switch_api_interface_get_from_ifindex(cpu_header->ingress_ifindex);
        intf_info = switch_api_interface_get(intf_handle);
        if (!intf_info) {
            return SWITCH_STATUS_INVALID_INTERFACE;
        }
        port_handle = SWITCH_INTF_PORT_HANDLE(intf_info);
        port_info = switch_api_port_get_internal(port_handle);
        if (!port_info) {
            return SWITCH_STATUS_INVALID_PORT_NUMBER;
        }
        hostif_handle = port_info->hostif_handle;
        hostif_info = switch_hostif_get(hostif_handle);
        if (!hostif_info) {
            return SWITCH_STATUS_INVALID_INTERFACE;
        }
        SWITCH_API_TRACE("Sending packet through netdev\n");
        switch_packet_tx_to_host(hostif_info, packet, packet_size);
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_hostif_tx_packet(switch_device_t device, switch_hostif_packet_t *hostif_packet)
{
    switch_packet_header_t             packet_header;
    switch_fabric_header_t            *fabric_header = NULL;
    switch_cpu_header_t               *cpu_header = NULL;
    switch_port_info_t                *port_info = NULL;

    SWITCH_API_TRACE("Received packet from host port %lx through cb\n",
                     hostif_packet->handle);

    memset(&packet_header, 0, sizeof(switch_packet_header_t));
    fabric_header = &packet_header.fabric_header;
    cpu_header = &packet_header.cpu_header;
    fabric_header->dst_device = device;
    if (hostif_packet->is_lag) {
        // Pick a member for lag
    } else {
        port_info = switch_api_port_get_internal(hostif_packet->handle);
        if (!port_info) {
            return SWITCH_STATUS_INVALID_PORT_NUMBER;
        }
        fabric_header->dst_port_or_group = SWITCH_PORT_ID(port_info);
    }
    fabric_header->packet_type = SWITCH_FABRIC_HEADER_TYPE_CPU;
    fabric_header->ether_type = SWITCH_FABRIC_HEADER_ETHTYPE;
    cpu_header->tx_bypass = hostif_packet->tx_bypass;
    switch_packet_tx_to_hw(&packet_header, hostif_packet->pkt, hostif_packet->pkt_size);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_hostif_rx_packet_from_host(switch_hostif_info_t *hostif_info, char *packet, int packet_size)
{
    switch_packet_header_t             packet_header;
    switch_fabric_header_t            *fabric_header = NULL;
    switch_cpu_header_t               *cpu_header = NULL;
    switch_device_t                    device = 0;
    switch_port_info_t                *port_info = NULL;

    SWITCH_API_TRACE("Received packet from host port %lx through netdev\n",
                     hostif_info->hostif.handle);

    fabric_header = &packet_header.fabric_header;
    cpu_header = &packet_header.cpu_header;
    fabric_header->dst_device = device;
    port_info = switch_api_port_get_internal(hostif_info->hostif.handle);
    if (!port_info) {
        return SWITCH_STATUS_INVALID_PORT_NUMBER;
    }
    fabric_header->packet_type = SWITCH_FABRIC_HEADER_TYPE_CPU;
    fabric_header->ether_type = SWITCH_FABRIC_HEADER_ETHTYPE;
    fabric_header->dst_port_or_group = SWITCH_PORT_ID(port_info);
    cpu_header->tx_bypass = TRUE;
    switch_packet_tx_to_hw(&packet_header, packet, packet_size);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_hostif_create()
{
    switch_handle_t hostif_handle;
    _switch_handle_create(SWITCH_HANDLE_TYPE_HOSTIF, switch_hostif_info_t,
                          switch_hostif_array, NULL, hostif_handle);
    return hostif_handle;
}

switch_hostif_info_t *
switch_hostif_get(switch_handle_t hostif_handle)
{
    switch_hostif_info_t *hostif_info = NULL;
    _switch_handle_get(switch_hostif_info_t, switch_hostif_array, hostif_handle, hostif_info);
    return hostif_info;
}

switch_status_t
switch_hostif_delete(switch_handle_t handle)
{
    _switch_handle_delete(switch_hostif_info_t, switch_hostif_array, handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_api_hostif_create(switch_device_t device, switch_hostif_t *hostif)
{
    switch_handle_t                    hostif_handle = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_hostif_info_t              *hostif_info = NULL;
    switch_handle_type_t               handle_type = 0;
    switch_port_info_t                *port_info = NULL;
    switch_interface_info_t           *intf_info = NULL;

    hostif_handle = switch_hostif_create();
    hostif_info = switch_hostif_get(hostif_handle);
    memcpy(&hostif_info->hostif, hostif, sizeof(switch_hostif_t));
    status = switch_packet_hostif_create(device, hostif_info);
    if (status != SWITCH_STATUS_SUCCESS) {
        // delete handle
        switch_hostif_delete(hostif_handle);
        return SWITCH_API_INVALID_HANDLE;
    }
    handle_type = switch_handle_get_type(hostif->handle);
    switch (handle_type) {
        case SWITCH_HANDLE_TYPE_PORT:
            port_info = switch_api_port_get_internal(hostif->handle);
            if (!port_info) {
                return SWITCH_STATUS_INVALID_PORT_NUMBER;
            }
            port_info->hostif_handle = hostif_handle;
            break;
        case SWITCH_HANDLE_TYPE_INTERFACE:
            //TODO: Add support for RIF
            intf_info = switch_api_interface_get(hostif->handle);
            if (!intf_info) {
                return SWITCH_STATUS_INVALID_INTERFACE;
            }
            intf_info->hostif_handle = hostif_handle;
            break;
        default:
            break;
    }
    SWITCH_API_TRACE("Host interface created %lu\n", hostif_handle);
    return hostif_handle;
}

switch_status_t
switch_api_hostif_delete(switch_device_t device, switch_handle_t hostif_handle)
{
    switch_hostif_info_t       *hostif_info = NULL;

    if (!SWITCH_HOSTIF_HANDLE_VALID(hostif_handle)) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    hostif_info = switch_hostif_get(hostif_handle);
    if (!hostif_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }
    switch_packet_hostif_delete(device, hostif_info);
    switch_hostif_delete(hostif_handle);
    SWITCH_API_TRACE("Host interface deleted %lu\n", hostif_handle);
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
switch_cpu_nhop_create(switch_device_t device, switch_hostif_reason_code_t rcode)
{
    switch_api_interface_info_t        api_intf_info;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_nhop_key_t                  nhop_key;
    switch_interface_info_t           *intf_info = NULL;
    switch_ifindex_t                   ifindex;
    switch_handle_t                    intf_handle;

    memset(&api_intf_info, 0, sizeof(switch_api_interface_info_t));
    memset(&nhop_key, 0, sizeof(switch_nhop_key_t));
    api_intf_info.u.port_lag_handle = CPU_PORT_ID;
    api_intf_info.type = SWITCH_API_INTERFACE_L2_VLAN_ACCESS;
    intf_handle = switch_api_interface_create(device, &api_intf_info);
    if (intf_handle == SWITCH_API_INVALID_HANDLE) {
        return SWITCH_STATUS_FAILURE;
    }

    intf_info = switch_api_interface_get(intf_handle);
    if (!intf_info) {
        return SWITCH_STATUS_FAILURE;
    }
    ifindex = SWITCH_HOSTIF_COMPUTE_IFINDEX(handle_to_id(intf_handle));
    intf_info->ifindex = ifindex;

    memset(&nhop_key, 0, sizeof(switch_nhop_key_t));
    nhop_key.intf_handle = intf_handle;
    nhop_key.ip_addr_valid = 0;
    hostif_nhop[rcode].nhop_handle = switch_api_nhop_create(device, &nhop_key);

    hostif_nhop[rcode].ifindex = ifindex;
    hostif_nhop[rcode].intf_handle = intf_handle;

    status = switch_pd_lag_group_table_add_entry(device,
                                     hostif_nhop[rcode].ifindex,
                                     CPU_PORT_ID,
                                     &(hostif_nhop[rcode].mbr_hdl),
                                     &(hostif_nhop[rcode].lag_entry));
    return status;
}

switch_status_t
switch_api_cpu_interface_create(switch_device_t device)
{
    switch_handle_t                    intf_handle = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_port_info_t                *port_info = NULL;

    status = switch_cpu_nhop_create(device, SWITCH_HOSTIF_REASON_CODE_NONE);
    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }
    intf_handle = hostif_nhop[SWITCH_HOSTIF_REASON_CODE_NONE].intf_handle;
    port_info = switch_api_port_get_internal(CPU_PORT_ID);
    if (!port_info) {
        return SWITCH_STATUS_INVALID_PORT_NUMBER;
    }
    port_info->intf_handle = intf_handle;
    status = switch_pd_rewrite_table_fabric_add_entry(device,
                                         SWITCH_EGRESS_TUNNEL_TYPE_CPU,
                                         handle_to_id(intf_handle),
                                         &port_info->rw_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }

    status = switch_pd_tunnel_rewrite_cpu_add_entry(device,
                                         handle_to_id(intf_handle),
                                         &port_info->tunnel_rw_entry);
    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }

    status = switch_pd_ingress_fabric_table_add_entry(device);
    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }

    switch_cpu_nhop_create(device, SWITCH_HOSTIF_REASON_CODE_GLEAN);
    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }

    switch_cpu_nhop_create(device, SWITCH_HOSTIF_REASON_CODE_MYIP);
    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }

    switch_cpu_nhop_create(device, SWITCH_HOSTIF_REASON_CODE_NULL_DROP);
    if (status != SWITCH_STATUS_SUCCESS) {
        return status;
    }
    return status;
}


switch_handle_t switch_api_cpu_nhop_get(switch_hostif_reason_code_t rcode)
{
    if (rcode > SWITCH_HOSTIF_REASON_CODE_MAX) {
        return SWITCH_API_INVALID_HANDLE;
    }
    return hostif_nhop[rcode].nhop_handle;
}

switch_ifindex_t switch_api_cpu_glean_ifindex() {
    return hostif_nhop[SWITCH_HOSTIF_REASON_CODE_GLEAN].ifindex;
}

switch_ifindex_t switch_api_cpu_myip_ifindex() {
    return hostif_nhop[SWITCH_HOSTIF_REASON_CODE_MYIP].ifindex;
}

switch_ifindex_t switch_api_drop_ifindex() {
    return hostif_nhop[SWITCH_HOSTIF_REASON_CODE_NULL_DROP].ifindex;
}

#ifdef __cplusplus
}
#endif
