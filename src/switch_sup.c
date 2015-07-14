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
#include "switchapi/switch_sup.h"
#include "switch_pd.h"
#include "switch_log.h"
#include "switch_sup_int.h"
#include "switch_packet_int.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static void *switch_sup_group_array;
static void *switch_sup_code_array;
static void *switch_sup_intf_array;
static switch_sup_rx_callback_fn rx_packet;
bool rx_callback_set = FALSE;
bool sup_code_all = FALSE;

switch_status_t
switch_sup_init(switch_device_t device)
{
    switch_sup_group_array = NULL;
    switch_sup_code_array = NULL;
    switch_sup_intf_array = NULL;
    switch_handle_type_init(SWITCH_HANDLE_TYPE_SUP_GROUP, (1024));
    switch_handle_type_init(SWITCH_HANDLE_TYPE_SUP_INTERFACE, (1024));
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_sup_group_free(switch_device_t device)
{
    switch_handle_type_free(SWITCH_HANDLE_TYPE_SUP_GROUP);
    switch_handle_type_free(SWITCH_HANDLE_TYPE_SUP_INTERFACE);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_sup_group_create()
{
    switch_handle_t sup_group_handle;
    _switch_handle_create(SWITCH_HANDLE_TYPE_SUP_GROUP, switch_sup_group_t,
                          switch_sup_group_array, NULL, sup_group_handle);
    return sup_group_handle;
}

switch_sup_group_t *
switch_sup_group_get(switch_handle_t sup_group_handle)
{
    switch_sup_group_t *sup_group = NULL;
    _switch_handle_get(switch_sup_group_t, switch_sup_group_array, sup_group_handle, sup_group);
    return sup_group;
}

switch_status_t
switch_sup_group_delete(switch_handle_t handle)
{
    _switch_handle_delete(switch_sup_group_t, switch_sup_group_array, handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_api_sup_group_create(switch_device_t device, switch_sup_group_t *sup_group)
{
    switch_handle_t                    sup_group_handle = 0;
    switch_sup_group_t                *sup_group_temp = NULL;

    sup_group_handle = switch_sup_group_create();
    sup_group_temp = switch_sup_group_get(sup_group_handle);
    memcpy(sup_group_temp, sup_group, sizeof(switch_sup_group_t));
    return sup_group_handle;
}

switch_status_t
switch_api_sup_group_delete(switch_device_t device, switch_handle_t sup_group_handle)
{
    switch_sup_group_t *sup_group = NULL;

    sup_group = switch_sup_group_get(sup_group_handle);
    if (!sup_group) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }
    switch_sup_group_delete(sup_group_handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_sup_code_create(switch_device_t device, switch_sup_code_info_t *sup_code_info)
{
    switch_sup_info_t                    *sup_info = NULL;
    switch_sup_info_t                    *sup_info_all = NULL;
    switch_sup_code_info_t               *sup_code_info_all = NULL;
    void                                 *temp = NULL;
    void                                 *temp_all = NULL;
    switch_acl_system_key_value_pair_t    acl_kvp[SWITCH_ACL_SYSTEM_FIELD_MAX];
    switch_acl_action_t                   acl_action;
    switch_acl_action_params_t            action_params;
    switch_handle_t                       acl_handle = 0;
    int                                   priority_shift = 8;
    int                                   priority;
    int                                   field_count = 0;
    switch_status_t                       status = SWITCH_STATUS_SUCCESS;
    switch_handle_t                       ace_handle;

    JLG(temp, switch_sup_code_array, sup_code_info->sup_code);
    if (!temp) {
        sup_info = switch_malloc(sizeof(switch_sup_info_t), 1);
        if (!sup_info) {
            return SWITCH_STATUS_NO_MEMORY;
        }
        JLI(temp, switch_sup_code_array, sup_code_info->sup_code);
        *(unsigned long *)temp = (unsigned long) (sup_info);

        if (!sup_code_all) {
            sup_info_all = switch_malloc(sizeof(switch_sup_info_t), 1);
            if (!sup_info_all) {
                return SWITCH_STATUS_NO_MEMORY;
            }
            sup_code_info_all = &sup_info_all->sup_code_info;
            JLI(temp_all, switch_sup_code_array, SWITCH_SUP_CODE_NONE);
            sup_code_info_all->sup_code = SWITCH_SUP_CODE_NONE;
            sup_code_info_all->channel = sup_code_info->channel;
            *(unsigned long *)temp_all = (unsigned long) (sup_info_all);
            sup_code_all = TRUE;
        }
    }
    sup_info = (switch_sup_info_t *) (*(unsigned long *)temp);
    memcpy(&sup_info->sup_code_info, sup_code_info, sizeof(switch_sup_code_info_t));
    acl_handle = switch_api_acl_list_create(device, SWITCH_ACL_TYPE_SYSTEM);
    memset(&acl_kvp, 0, sizeof(switch_acl_system_key_value_pair_t));
    priority = sup_code_info->priority << priority_shift;
    switch (sup_code_info->sup_code) {
        case SWITCH_SUP_CODE_STP:
            // stp bpdu, redirect to cpu
            acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_DEST_MAC;
            acl_kvp[0].value.dest_mac.mac_addr[0] = 0x01;
            acl_kvp[0].value.dest_mac.mac_addr[1] = 0x80;
            acl_kvp[0].value.dest_mac.mac_addr[2] = 0xC2;
            acl_kvp[0].value.dest_mac.mac_addr[3] = 0x00;
            acl_kvp[0].value.dest_mac.mac_addr[4] = 0x00;
            acl_kvp[0].value.dest_mac.mac_addr[5] = 0x00;
            acl_kvp[0].mask.u.mask = 0xFFFFFFFFFFFF;
            acl_action = sup_code_info->action;
            field_count = 1;
            action_params.sup_redirect.sup_code = sup_code_info->sup_code;
            switch_api_acl_rule_create(device, acl_handle, 
                               priority, field_count,
                               acl_kvp, acl_action,
                               &action_params, &ace_handle);
            status = switch_api_acl_reference(device, acl_handle, 0);
            break;
        case SWITCH_SUP_CODE_LACP:
            // lacp bpdu, redirect to cpu
            acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_DEST_MAC;
            acl_kvp[0].value.dest_mac.mac_addr[0] = 0x01;
            acl_kvp[0].value.dest_mac.mac_addr[1] = 0x80;
            acl_kvp[0].value.dest_mac.mac_addr[2] = 0xC2;
            acl_kvp[0].value.dest_mac.mac_addr[3] = 0x00;
            acl_kvp[0].value.dest_mac.mac_addr[4] = 0x00;
            acl_kvp[0].value.dest_mac.mac_addr[5] = 0x02;
            acl_kvp[0].mask.u.mask = 0xFFFFFFFFFFFF;
            acl_action = sup_code_info->action;
            field_count = 1;
            action_params.sup_redirect.sup_code = sup_code_info->sup_code;
            switch_api_acl_rule_create(device, acl_handle, 
                               priority, field_count,
                               acl_kvp, acl_action,
                               &action_params, &ace_handle);
            status = switch_api_acl_reference(device, acl_handle, 0);
            break;
        case SWITCH_SUP_CODE_LLDP:
            // lacp frame, redirect to cpu
            acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_DEST_MAC;
            acl_kvp[0].value.dest_mac.mac_addr[0] = 0x01;
            acl_kvp[0].value.dest_mac.mac_addr[1] = 0x80;
            acl_kvp[0].value.dest_mac.mac_addr[2] = 0xC2;
            acl_kvp[0].value.dest_mac.mac_addr[3] = 0x00;
            acl_kvp[0].value.dest_mac.mac_addr[4] = 0x00;
            acl_kvp[0].value.dest_mac.mac_addr[5] = 0x0e;
            acl_kvp[0].mask.u.mask = 0xFFFFFFFFFFFF;
            acl_kvp[1].value.eth_type = 0x88CC;
            acl_kvp[1].mask.u.mask = 0xFFFF;
            acl_action = sup_code_info->action;
            field_count = 2;
            action_params.sup_redirect.sup_code = sup_code_info->sup_code;
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
            acl_kvp[1].value.eth_type = 0x88CC;
            acl_kvp[1].mask.u.mask = 0xFFFF;
            acl_action = sup_code_info->action;
            field_count = 2;
            action_params.sup_redirect.sup_code = sup_code_info->sup_code;
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
            acl_kvp[1].value.eth_type = 0x88CC;
            acl_kvp[1].mask.u.mask = 0xFFFF;
            acl_action = sup_code_info->action;
            field_count = 2;
            action_params.sup_redirect.sup_code = sup_code_info->sup_code;
            priority++;
            switch_api_acl_rule_create(device, acl_handle, 
                               priority, field_count,
                               acl_kvp, acl_action,
                               &action_params, &ace_handle);
            status = switch_api_acl_reference(device, acl_handle, 0);
            break;
        case SWITCH_SUP_CODE_OSPF:
            // All OSPF routers 224.0.0.5, copy to cpu
            acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_IPV4_DEST;
            acl_kvp[0].value.ipv4_dest = 0xE0000005;
            acl_kvp[0].mask.u.mask = 0xFFFFFFFF;
            acl_kvp[1].field = SWITCH_ACL_SYSTEM_FIELD_IP_PROTO;
            acl_kvp[1].value.ip_proto = 89;
            acl_kvp[1].mask.u.mask = 0xFFFF;
            acl_action = sup_code_info->action;
            field_count = 2;
            action_params.sup_redirect.sup_code = sup_code_info->sup_code;
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
            acl_action = sup_code_info->action;
            field_count = 2;
            action_params.sup_redirect.sup_code = sup_code_info->sup_code;
            switch_api_acl_rule_create(device, acl_handle, 
                               priority + 1, field_count,
                               acl_kvp, acl_action,
                               &action_params, &ace_handle);
            status = switch_api_acl_reference(device, acl_handle, 0);
            break;
        case SWITCH_SUP_CODE_PIM:
            // PIM packet, copy to cpu
            acl_kvp[0].field = SWITCH_ACL_SYSTEM_FIELD_IP_PROTO;
            acl_kvp[0].value.ip_proto = 103; 
            acl_kvp[0].mask.u.mask = 0xFFFF;
            acl_action = sup_code_info->action;
            field_count = 1;
            action_params.sup_redirect.sup_code = sup_code_info->sup_code;
            switch_api_acl_rule_create(device, acl_handle, 
                               priority, field_count,
                               acl_kvp, acl_action,
                               &action_params, &ace_handle);
            status = switch_api_acl_reference(device, acl_handle, 0);
            break;
        default:
            status = SWITCH_STATUS_NOT_SUPPORTED;
            break;
    }
    return status;
}

switch_status_t
switch_api_sup_code_update(switch_device_t device, switch_sup_code_info_t *sup_code_info)
{
    switch_sup_info_t                 *sup_info = NULL;
    void                              *temp = NULL;
    switch_sup_code_info_t            *sup_code_info_temp = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    bool                               action_set = FALSE;
    bool                               priority_set = FALSE;

    JLG(temp, switch_sup_code_array, sup_code_info->sup_code);
    if (!temp) {
        sup_info = switch_malloc(sizeof(switch_sup_info_t), 1);
        if (!sup_info) {
            return SWITCH_STATUS_NO_MEMORY;
        }
        JLI(temp, switch_sup_code_array, sup_code_info->sup_code);
        *(unsigned long *)temp = (unsigned long) (sup_info);
    }
    sup_info = (switch_sup_info_t *) (*(unsigned long *)temp);
    sup_code_info_temp = &sup_info->sup_code_info;

    if (sup_code_info->action) {
        sup_code_info_temp->action = sup_code_info->action;
        action_set = TRUE;
    } else if (sup_code_info_temp->action) {
        action_set = TRUE;
    }

    if (sup_code_info->priority) {
        sup_code_info_temp->priority = sup_code_info->priority;
        priority_set = TRUE;
    } else if (sup_code_info_temp->priority) {
        priority_set = TRUE;
    }

    if (sup_code_info->channel) {
        sup_code_info_temp->channel = sup_code_info->channel;
    }

    if (sup_code_info->sup_group_id) {
        sup_code_info_temp->sup_group_id = sup_code_info->sup_group_id;
    }

    if (action_set && priority_set) {
        status = switch_api_sup_code_create(device, sup_code_info_temp);
    }
    return status;
}

switch_status_t
switch_api_sup_code_delete(switch_device_t device, switch_sup_code_t sup_code)
{
    switch_sup_info_t                 *sup_info = NULL;
    switch_sup_code_info_t            *sup_code_info = NULL;
    void                              *temp = NULL;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    int                                priority_shift = 8;
    int                                priority = 0;

    JLG(temp, switch_sup_code_array, sup_code);
    if (!temp) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    sup_info = (switch_sup_info_t *) (*(unsigned long *)temp);
    sup_code_info = &sup_info->sup_code_info;
    priority = sup_code_info->priority << priority_shift;
    switch (sup_code_info->sup_code) {
        case SWITCH_SUP_CODE_STP:
            status = switch_api_acl_rule_delete(device, sup_info->acl_handle, priority);
            status = switch_api_acl_remove(device, sup_info->acl_handle, 0);
            break;
        case SWITCH_SUP_CODE_LACP:
            status = switch_api_acl_rule_delete(device, sup_info->acl_handle, priority);
            status = switch_api_acl_remove(device, sup_info->acl_handle, 0);
            break;
        case SWITCH_SUP_CODE_LLDP:
            status = switch_api_acl_rule_delete(device, sup_info->acl_handle, priority);
            priority++;
            status = switch_api_acl_rule_delete(device, sup_info->acl_handle, priority);
            priority++;
            status = switch_api_acl_rule_delete(device, sup_info->acl_handle, priority);
            status = switch_api_acl_remove(device, sup_info->acl_handle, 0);
            break;
        case SWITCH_SUP_CODE_OSPF:
            status = switch_api_acl_rule_delete(device, sup_info->acl_handle, priority);
            priority++;
            status = switch_api_acl_rule_delete(device, sup_info->acl_handle, priority);
            status = switch_api_acl_remove(device, sup_info->acl_handle, 0);
            break;
        case SWITCH_SUP_CODE_PIM:
            status = switch_api_acl_rule_delete(device, sup_info->acl_handle, priority);
            status = switch_api_acl_remove(device, sup_info->acl_handle, 0);
            break;
        default:
            status = SWITCH_STATUS_NOT_SUPPORTED;
            break;
    }
    return status;
}

switch_status_t
switch_api_sup_register_rx_callback(switch_device_t device, switch_sup_rx_callback_fn cb_fn)
{
    rx_packet = cb_fn;
    rx_callback_set = TRUE;
    return SWITCH_STATUS_SUCCESS;
}


switch_status_t
switch_api_sup_deregister_rx_callback(switch_device_t device, switch_sup_rx_callback_fn cb_fn)
{
    rx_callback_set = FALSE;
    return SWITCH_STATUS_SUCCESS;
}

const char *
switch_api_sup_code_string(switch_sup_code_t sup_code)
{
    switch (sup_code) {
        case SWITCH_SUP_CODE_STP:
            return "stp";
        case SWITCH_SUP_CODE_LACP:
            return "lacp";
        case SWITCH_SUP_CODE_LLDP:
            return "lldp";
        case SWITCH_SUP_CODE_OSPF:
            return "ospf";
        case SWITCH_SUP_CODE_PIM:
            return "pim";
        default:
            return "unknown";
    }
}

switch_status_t
switch_api_sup_rx_packet_from_hw(switch_packet_header_t *packet_header, char *packet, int packet_size)
{
    switch_fabric_header_t            *fabric_header = NULL;
    switch_cpu_header_t               *cpu_header = NULL;
    switch_sup_info_t                 *sup_info = NULL;
    switch_interface_info_t           *intf_info = NULL;
    void                              *temp = NULL;
    switch_sup_packet_t               sup_packet;
    switch_handle_t                   intf_handle = 0;
    switch_handle_t                   port_handle = 0;
    switch_handle_t                   sup_intf_handle = 0;
    switch_port_info_t               *port_info = NULL;
    switch_sup_interface_info_t      *sup_intf_info = NULL;

    memset(&sup_packet, 0, sizeof(switch_sup_packet_t));
    fabric_header = &packet_header->fabric_header;
    cpu_header = &packet_header->cpu_header;
    JLG(temp, switch_sup_code_array, cpu_header->sup_code);
    if (!temp) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }

    SWITCH_API_TRACE("Received packet with %s trap on ifindex %x\n",
                     switch_api_sup_code_string(cpu_header->sup_code),
                     fabric_header->ingress_ifindex);

    sup_info = (switch_sup_info_t *) (*(unsigned long *)temp);
    if (sup_info->sup_code_info.channel == SWITCH_CHANNEL_CB) {
        sup_packet.sup_code = cpu_header->sup_code;
        sup_packet.pkt = packet;
        sup_packet.pkt_size = packet_size;

        intf_handle = switch_api_interface_get_from_ifindex(fabric_header->ingress_ifindex);
        intf_info = switch_api_interface_get(intf_handle);
        if (!intf_info) {
            return SWITCH_STATUS_INVALID_INTERFACE;
        }
        sup_packet.handle = intf_info->api_intf_info.u.port_lag_handle;
        if (SWITCH_IS_LAG_IFINDEX(fabric_header->ingress_ifindex)) {
            sup_packet.is_lag = TRUE;
        }
        if (!rx_callback_set) {
            return SWITCH_STATUS_ITEM_NOT_FOUND;
        }
        SWITCH_API_TRACE("Sending packet through cb\n");
        rx_packet(&sup_packet);
    } else if (sup_info->sup_code_info.channel == SWITCH_CHANNEL_NETDEV) {
        port_handle = switch_api_interface_get_from_ifindex(fabric_header->ingress_ifindex);
        port_info = switch_api_port_get_internal(port_handle);
        if (!port_info) {
            return SWITCH_STATUS_ITEM_NOT_FOUND;
        }
        sup_intf_handle = port_info->sup_intf_handle;
        sup_intf_info = switch_sup_interface_get(sup_intf_handle);
        if (!port_info) {
            return SWITCH_STATUS_ITEM_NOT_FOUND;
        }
        SWITCH_API_TRACE("Sending packet through netdev\n");
        switch_packet_tx_to_host(sup_intf_info, packet, packet_size);
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_sup_tx_packet_to_hw(switch_device_t device, switch_sup_packet_t *sup_packet)
{
    switch_packet_header_t             packet_header;
    switch_fabric_header_t            *fabric_header = NULL;
    switch_cpu_header_t               *cpu_header = NULL;
    switch_port_info_t                *port_info = NULL;

    SWITCH_API_TRACE("Received packet from host port %lu through cb\n",
                     sup_packet->handle);

    memset(&packet_header, 0, sizeof(switch_packet_header_t));
    fabric_header = &packet_header.fabric_header;
    cpu_header = &packet_header.cpu_header;
    fabric_header->dst_device = device;
    if (sup_packet->is_lag) {
        // Pick a member for lag
    } else {
        port_info = switch_api_port_get_internal(sup_packet->handle);
        if (!port_info) {
            return SWITCH_STATUS_ITEM_NOT_FOUND;
        }
        fabric_header->dst_port_or_group = SWITCH_PORT_ID(port_info);
    }
    fabric_header->packet_type = SWITCH_FABRIC_HEADER_TYPE_CPU;
    fabric_header->ether_type = SWITCH_FABRIC_HEADER_ETHTYPE;
    cpu_header->tx_bypass = sup_packet->tx_bypass;
    switch_packet_tx_to_hw(&packet_header, sup_packet->pkt, sup_packet->pkt_size);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_sup_rx_packet_from_host(switch_sup_interface_info_t *sup_intf_info, char *packet, int packet_size)
{
    switch_packet_header_t             packet_header;
    switch_fabric_header_t            *fabric_header = NULL;
    switch_cpu_header_t               *cpu_header = NULL;
    switch_device_t                    device = 0;
    switch_port_info_t                *port_info = NULL;

    SWITCH_API_TRACE("Received packet from host port %lu through netdev\n",
                     sup_intf_info->sup_interface.handle);

    fabric_header = &packet_header.fabric_header;
    cpu_header = &packet_header.cpu_header;
    fabric_header->dst_device = device;
    port_info = switch_api_port_get_internal(sup_intf_info->sup_interface.handle);
    if (!port_info) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    fabric_header->packet_type = SWITCH_FABRIC_HEADER_TYPE_CPU;
    fabric_header->ether_type = SWITCH_FABRIC_HEADER_ETHTYPE;
    fabric_header->dst_port_or_group = SWITCH_PORT_ID(port_info);
    cpu_header->tx_bypass = TRUE;
    switch_packet_tx_to_hw(&packet_header, packet, packet_size);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_sup_interface_create()
{
    switch_handle_t sup_intf_handle;
    _switch_handle_create(SWITCH_HANDLE_TYPE_SUP_INTERFACE, switch_sup_interface_info_t,
                          switch_sup_intf_array, NULL, sup_intf_handle);
    return sup_intf_handle;
}

switch_sup_interface_info_t *
switch_sup_interface_get(switch_handle_t sup_intf_handle)
{
    switch_sup_interface_info_t *sup_intf = NULL;
    _switch_handle_get(switch_sup_interface_info_t, switch_sup_intf_array, sup_intf_handle, sup_intf);
    return sup_intf;
}

switch_status_t
switch_sup_interface_delete(switch_handle_t handle)
{
    _switch_handle_delete(switch_sup_interface_info_t, switch_sup_intf_array, handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_api_sup_interface_create(switch_device_t device, switch_sup_interface_t *sup_interface)
{
    switch_handle_t                    sup_intf_handle = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_sup_interface_info_t       *sup_intf_info = NULL;
    switch_handle_type_t               handle_type = 0;
    switch_port_info_t                *port_info = NULL;

    sup_intf_handle = switch_sup_interface_create();
    sup_intf_info = switch_sup_interface_get(sup_intf_handle);
    memcpy(&sup_intf_info->sup_interface, sup_interface, sizeof(switch_sup_interface_t));
    status = switch_packet_sup_host_interface_create(sup_intf_info);
    if (status != SWITCH_STATUS_SUCCESS) {
        return SWITCH_API_INVALID_HANDLE;
    }
    handle_type = switch_handle_get_type(sup_interface->handle);
    switch (handle_type) {
        case SWITCH_HANDLE_TYPE_PORT:
            port_info = switch_api_port_get_internal(sup_interface->handle);
            port_info->sup_intf_handle = sup_intf_handle;
            break;
        case SWITCH_HANDLE_TYPE_INTERFACE:
            //TODO: Add support for RIF
            break;
        default:
            break;
    }
    SWITCH_API_TRACE("Host interface created %lu\n", sup_intf_handle);
    return sup_intf_handle;
}

switch_status_t
switch_api_sup_interface_delete(switch_device_t device, switch_handle_t sup_intf_handle)
{
    switch_sup_interface_info_t       *sup_intf_info = NULL;

    sup_intf_info = switch_sup_interface_get(sup_intf_handle);
    if (!sup_intf_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }
    switch_sup_interface_delete(sup_intf_handle);
    SWITCH_API_TRACE("Host interface deleted %lu\n", sup_intf_handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_cpu_interface_create(switch_device_t device)
{
    switch_handle_t                    intf_handle = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;
    switch_api_interface_info_t        api_intf_info;
    switch_port_info_t                *port_info = NULL;

    memset(&api_intf_info, 0, sizeof(switch_api_interface_info_t));
    api_intf_info.u.port_lag_handle = CPU_PORT_ID;
    api_intf_info.type = SWITCH_API_INTERFACE_L2_VLAN_ACCESS;
    intf_handle = switch_api_interface_create(device, &api_intf_info);
    port_info = switch_api_port_get_internal(CPU_PORT_ID);
    port_info->intf_handle = intf_handle;
    status = switch_pd_rewrite_table_fabric_add_entry(device,
                                         SWITCH_EGRESS_TUNNEL_TYPE_CPU,
                                         handle_to_id(intf_handle),
                                         &port_info->rw_entry);
    status = switch_pd_tunnel_rewrite_cpu_add_entry(device,
                                         handle_to_id(intf_handle),
                                         &port_info->tunnel_rw_entry);
    status = switch_pd_ingress_fabric_table_add_entry(device);
    status = switch_pd_mirror_add_session(CPU_MIRROR_SESSION_ID, CPU_PORT_ID);

    return status;
}

#ifdef __cplusplus
}
#endif
