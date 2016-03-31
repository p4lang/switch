/*
Copyright 2016-present Barefoot Networks, Inc.

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

#include <sail2mc.h>
#include "saiinternal.h"
#include <switchapi/switch_port.h>
#include <switchapi/switch_vlan.h>
#include <switchapi/switch_interface.h>
#include <switchapi/switch_mcast.h>

static sai_api_t api_id = SAI_API_L2MC;

#if 0
static void sai_l2mc_entry_to_string(
        _In_ const sai_l2mc_entry_t *l2mc_entry,
        _Out_ char *entry_string) {
    int count = 0;
    int len = 0;
    count = snprintf(entry_string, SAI_MAX_ENTRY_STRING_LEN,
                     "l2mc: vlan id 0x%x (", l2mc_entry->vlan_id);
    if (count > SAI_MAX_ENTRY_STRING_LEN) {
        return;
    }
    sai_ipaddress_to_string(l2mc_entry->group,
                            SAI_MAX_ENTRY_STRING_LEN - count,
                            entry_string + count, &len);
    count += len;
    if (count > SAI_MAX_ENTRY_STRING_LEN) {
        return;
    }
    count += snprintf(entry_string + count,
                      SAI_MAX_ENTRY_STRING_LEN - count, ")");
    return;
}
#endif

static bool sai_l2mc_entry_parse(
        _In_ const sai_l2mc_entry_t *l2mc_entry,
        _Out_ switch_handle_t *vlan_handle,
        _Out_ switch_ip_addr_t *src_addr,
        _Out_ switch_ip_addr_t *grp_addr) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    switch_status = switch_api_vlan_id_to_handle_get(
        (switch_vlan_t) l2mc_entry->vlan_id, vlan_handle);
    status = sai_switch_status_to_sai_status(switch_status);
    if (status != SAI_STATUS_SUCCESS) {
        return false;
    }

    memset(src_addr, 0, sizeof(switch_ip_addr_t));
    memset(grp_addr, 0, sizeof(switch_ip_addr_t));
    sai_ip_addr_to_switch_ip_addr(&(l2mc_entry->source), src_addr);
    if (((src_addr->type == SWITCH_API_IP_ADDR_V4) &&
         (src_addr->ip.v4addr == 0)) ||
        ((src_addr->type == SWITCH_API_IP_ADDR_V6) &&
         (memcmp(src_addr->ip.v6addr, &in6addr_any,
                 sizeof(in6addr_any)) == 0))) {
        src_addr->prefix_len = 0;
    }
    sai_ip_addr_to_switch_ip_addr(&(l2mc_entry->group), grp_addr);
    return true;
}

static void sai_l2mc_entry_attribute_parse(
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list,
        _Out_ switch_handle_t **port_list_handle,
        _Out_ int *port_list_count,
        _Out_ int *action,
        _Out_ int *pri) {
    const sai_attribute_t *attribute;
    uint32_t index = 0;

    *action = SAI_PACKET_ACTION_FORWARD;
    for (index = 0; index < attr_count; index++) {
        attribute = &attr_list[index];
        switch (attribute->id) {
            case SAI_L2MC_ATTR_PORT_LIST:
                *port_list_count = attribute->value.objlist.count;
                *port_list_handle =
                    (switch_handle_t *) attribute->value.objlist.list;
                break;
            case SAI_ROUTE_ATTR_TRAP_PRIORITY:
                *pri = attribute->value.u8;
                break;
            case SAI_ROUTE_ATTR_PACKET_ACTION:
                *action = attribute->value.s32;
                break;
        }
    }
}

/*
 * Routine Description:
 *    Create L2 multicast entry
 *
 * Arguments:
 *    [in] l2mc_entry - L2 multicast entry
 *    [in] attr_count - number of attributes
 *    [in] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t sai_create_l2mc_entry(
        _In_ const sai_l2mc_entry_t *l2mc_entry,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    switch_ip_addr_t src_addr;
    switch_ip_addr_t grp_addr;
    switch_handle_t vlan_handle = 0;
    switch_handle_t *port_list_handle = 0;
    int port_list_count = 0;
    int action=-1, pri=-1;

    if (!l2mc_entry) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null l2mc entry: %s", sai_status_to_string(status));
        return status;
    }

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s", sai_status_to_string(status));
        return status;
    }

    sai_l2mc_entry_parse(l2mc_entry, &vlan_handle, &src_addr, &grp_addr);
    sai_l2mc_entry_attribute_parse(attr_count, attr_list,
                                   &port_list_handle, &port_list_count,
                                   &action, &pri);

    switch_handle_t mcast_hdl;
    mcast_hdl = switch_api_multicast_tree_create(device);

    switch_vlan_interface_t *mbrs;
    mbrs = switch_malloc(sizeof(switch_vlan_interface_t), port_list_count);
    for (int i = 0; i < port_list_count; i++) {
        mbrs[i].vlan_handle = vlan_handle;
        mbrs[i].intf_handle = port_list_handle[i];
    }

    switch_status = switch_api_multicast_member_add(device, mcast_hdl,
                                                    port_list_count, mbrs);

    switch_free(mbrs);
    status = sai_switch_status_to_sai_status(switch_status);
    if (switch_status == SWITCH_STATUS_SUCCESS) {
        switch_status = switch_api_multicast_l2route_add(device, mcast_hdl,
                                                         vlan_handle,
                                                         &src_addr, &grp_addr);
        status = sai_switch_status_to_sai_status(switch_status);
    }

    SAI_LOG_EXIT();

    return status;
}

/**
 * Routine Description:
 *    Remove L2 multicast entry
 *
 * Arguments:
 *    [in] l2mc_entry - L2 multicast entry
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t sai_remove_l2mc_entry(
        _In_ const sai_l2mc_entry_t *l2mc_entry) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    switch_ip_addr_t src_addr;
    switch_ip_addr_t grp_addr;
    switch_handle_t vlan_handle = 0;
    switch_handle_t mgid_handle = 0;

    if (!l2mc_entry) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null l2mc entry: %s", sai_status_to_string(status));
        return status;
    }

    sai_l2mc_entry_parse(l2mc_entry, &vlan_handle, &src_addr, &grp_addr);
    switch_status = switch_api_multicast_l2route_tree_get(device, vlan_handle,
                                                          &src_addr, &grp_addr,
                                                          &mgid_handle);
    assert(switch_handle_get_type(mgid_handle) == SWITCH_HANDLE_TYPE_MGID);
    switch_status = switch_api_multicast_tree_delete(device, mgid_handle);
    status = sai_switch_status_to_sai_status(switch_status);
    if (switch_status == SWITCH_STATUS_SUCCESS) {
        switch_status = switch_api_multicast_l2route_delete(
            device, vlan_handle, &src_addr, &grp_addr);
        status = sai_switch_status_to_sai_status(switch_status);
    }

    SAI_LOG_EXIT();

    return status;
}

/**
 * Routine Description:
 *    Set L2 multicast entry attribute value
 *
 * Arguments:
 *    [in] l2mc_entry - L2 multicast entry
 *    [in] attr - attribute
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t sai_set_l2mc_entry_attribute(
        _In_ const sai_l2mc_entry_t *l2mc_entry,
        _In_ const sai_attribute_t *attr) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;

    SAI_LOG_EXIT();

    return status;
}

/**
 * Routine Description:
 *    Get L2 multicast entry attribute value
 *
 * Arguments:
 *    [in] l2mc_entry - L2 multicast entry
 *    [in] attr_count - number of attributes
 *    [inout] attr_list - array of attributes
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t sai_get_l2mc_entry_attribute(
        _In_ const sai_l2mc_entry_t *l2mc_entry,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;

    SAI_LOG_EXIT();

    return status;
}

/**
 * Routine Description:
 *    Add ports to L2 multicast
 *
 * Arguments:
 *    [in] l2mc_entry - L2 multicast entry
 *    [in] port_count - number of ports
 *    [in] port_list  - port list
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t sai_add_ports_to_l2mc_entry(
        _In_ const sai_l2mc_entry_t *l2mc_entry,
        _In_ uint32_t port_count,
        _In_ const sai_object_list_t *port_list) {

    sai_status_t status = SAI_STATUS_SUCCESS;

    SAI_LOG_EXIT();

    return status;
}

/**
 * Routine Description:
 *    Remove ports from L2 multicast
 *
 * Arguments:
 *    [in] l2mc_entry - L2 multicast entry
 *    [in] port_count - number of ports
 *    [in] port_list  - port list
 *
 * Return Values:
 *    SAI_STATUS_SUCCESS on success
 *    Failure status code on error
 */
sai_status_t sai_remove_ports_from_l2mc_entry(
        _In_ const sai_l2mc_entry_t *l2mc_entry,
        _In_ uint32_t port_count,
        _In_ const sai_object_list_t *port_list) {

    sai_status_t status = SAI_STATUS_SUCCESS;

    SAI_LOG_EXIT();

    return status;
}

/**
 * L2 multicast method table retrieved with sai_api_query()
 */
sai_l2mc_api_t l2mc_api = {
    .create_l2mc_entry             =       sai_create_l2mc_entry,
    .remove_l2mc_entry             =       sai_remove_l2mc_entry,
    .set_l2mc_entry_attribute      =       sai_set_l2mc_entry_attribute,
    .get_l2mc_entry_attribute      =       sai_get_l2mc_entry_attribute,
    .add_ports_to_l2mc_entry       =       sai_add_ports_to_l2mc_entry,
    .remove_ports_from_l2mc_entry  =       sai_remove_ports_from_l2mc_entry,
};

sai_status_t sai_l2mc_initialize(sai_api_service_t *sai_api_service) {
    SAI_LOG_DEBUG("Initializing l2mc");
    sai_api_service->l2mc_api = l2mc_api;
    return SAI_STATUS_SUCCESS;
}
