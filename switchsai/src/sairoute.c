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

#include <sairoute.h>
#include "saiinternal.h"
#include <switchapi/switch_l3.h>
#include <switchapi/switch_hostif.h>

static sai_api_t api_id = SAI_API_ROUTE;

static void sai_route_entry_to_string(
        _In_ const sai_unicast_route_entry_t* unicast_route_entry,
        _Out_ char *entry_string) {
    int count = 0;
    int len = 0;
    count = snprintf(entry_string,
                     SAI_MAX_ENTRY_STRING_LEN,
                     "route: vrf %lx",
                     unicast_route_entry->vr_id);
    sai_ipprefix_to_string(unicast_route_entry->destination,
                           SAI_MAX_ENTRY_STRING_LEN - count,
                           entry_string + count, &len);
    return;
}

static void sai_route_entry_parse(
        _In_ const sai_unicast_route_entry_t* unicast_route_entry,
        _Out_ switch_handle_t *vrf_handle,
        _Out_ switch_ip_addr_t *ip_addr) {
    const sai_ip_prefix_t *sai_ip_prefix;

    SAI_ASSERT(sai_object_type_query(unicast_route_entry->vr_id) ==
               SAI_OBJECT_TYPE_VIRTUAL_ROUTER);
    *vrf_handle = (switch_handle_t) unicast_route_entry->vr_id;

    memset(ip_addr, 0, sizeof(switch_ip_addr_t));
    sai_ip_prefix = &unicast_route_entry->destination;
    sai_ip_prefix_to_switch_ip_addr(sai_ip_prefix, ip_addr);
}

static void sai_route_entry_attribute_parse(
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list,
        switch_handle_t *nhop_handle,
        int *action, int *pri) {
    const sai_attribute_t *attribute;
    uint32_t index = 0;

    for (index = 0; index < attr_count; index++) {
        attribute = &attr_list[index];
        switch (attribute->id) {
            case SAI_ROUTE_ATTR_NEXT_HOP_ID:
                *nhop_handle = (switch_handle_t) attribute->value.oid;
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
*    Create Route
*
* Arguments:
*    [in] unicast_route_entry - route entry
*    [in] attr_count - number of attributes
*    [in] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
* 
* Note: IP prefix/mask expected in Network Byte Order.
*   
*/
sai_status_t sai_create_route_entry(
        _In_ const sai_unicast_route_entry_t* unicast_route_entry,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    switch_ip_addr_t ip_addr;
    switch_handle_t nhop_handle = 0;
    switch_handle_t vrf_handle = 0;
    char entry_string[SAI_MAX_ENTRY_STRING_LEN];
    int action=-1, pri=-1;

    if (!unicast_route_entry) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null unicast entry: %s",
                       sai_status_to_string(status));
        return status;
    }

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s",
                       sai_status_to_string(status));
        return status;
    }

    sai_route_entry_parse(unicast_route_entry, &vrf_handle, &ip_addr);
    sai_route_entry_attribute_parse(attr_count, attr_list, &nhop_handle, &action, &pri);

    sai_route_entry_to_string(unicast_route_entry, entry_string);

    if(!nhop_handle && action != -1) {
        switch(action) {
            case SAI_PACKET_ACTION_DROP:
                nhop_handle = switch_api_cpu_nhop_get(SWITCH_HOSTIF_REASON_CODE_NULL_DROP);
                break;
            case SAI_PACKET_ACTION_FORWARD:
                break;
            case SAI_PACKET_ACTION_TRAP:
                nhop_handle = switch_api_cpu_nhop_get(SWITCH_HOSTIF_REASON_CODE_GLEAN);
                break;
            default:
                break;
        }
    }
    if (nhop_handle) {
        switch_status = switch_api_l3_route_add(device, vrf_handle, &ip_addr, nhop_handle);
        status = sai_switch_status_to_sai_status(switch_status);
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Remove Route
*
* Arguments:
*    [in] unicast_route_entry - route entry
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*
* Note: IP prefix/mask expected in Network Byte Order.
*/
sai_status_t sai_remove_route_entry(
        _In_ const sai_unicast_route_entry_t* unicast_route_entry) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    switch_ip_addr_t ip_addr;
    switch_handle_t vrf_handle = 0;
    switch_handle_t nhop_handle = 0;

    if (!unicast_route_entry) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null unicast entry: %s",
                       sai_status_to_string(status));
        return status;
    }

    sai_route_entry_parse(unicast_route_entry, &vrf_handle, &ip_addr);
    switch_status = switch_api_l3_route_delete(device, vrf_handle, &ip_addr, nhop_handle);
    status = sai_switch_status_to_sai_status(switch_status);

    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to remove route entry: %s",
                       sai_status_to_string(status));
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Set route attribute value
*
* Arguments:
*    [in] unicast_route_entry - route entry
*    [in] attr - attribute
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_set_route_entry_attribute(
        _In_ const sai_unicast_route_entry_t* unicast_route_entry,
        _In_ const sai_attribute_t *attr) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;

    if (!unicast_route_entry) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null unicast entry: %s",
                       sai_status_to_string(status));
        return status;
    }

    if (!attr) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute: %s",
                       sai_status_to_string(status));
        return status;
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Get route attribute value
*
* Arguments:
*    [in] unicast_route_entry - route entry
*    [in] attr_count - number of attributes
*    [inout] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_get_route_entry_attribute(
        _In_ const sai_unicast_route_entry_t* unicast_route_entry,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;

    if (!unicast_route_entry) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null unicast entry: %s",
                       sai_status_to_string(status));
        return status;
    }

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s",
                       sai_status_to_string(status));
        return status;
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
*  Router entry methods table retrieved with sai_api_query()
*/
sai_route_api_t route_api = {
    .create_route                  =             sai_create_route_entry,
    .remove_route                  =             sai_remove_route_entry,
    .set_route_attribute           =             sai_set_route_entry_attribute,
    .get_route_attribute           =             sai_get_route_entry_attribute,
};

sai_status_t sai_route_initialize(sai_api_service_t *sai_api_service) {
    SAI_LOG_DEBUG("Initializing route");
    sai_api_service->route_api = route_api;
    return SAI_STATUS_SUCCESS;
}
