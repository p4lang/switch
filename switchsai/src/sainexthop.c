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

#include <sainexthop.h>
#include "saiinternal.h"
#include <switchapi/switch_nhop.h>

static sai_api_t api_id = SAI_API_NEXT_HOP;

/*
* Routine Description:
*    Create next hop
*
* Arguments:
*    [out] next_hop_id - next hop id
*    [in] attr_count - number of attributes
*    [in] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*
* Note: IP address expected in Network Byte Order.
*/
sai_status_t sai_create_next_hop_entry(
        _Out_ sai_object_id_t* next_hop_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list) {

    SAI_LOG_ENTER();

    const sai_attribute_t *attribute;
    sai_status_t status = SAI_STATUS_SUCCESS;
    uint32_t index = 0;
    const sai_ip_address_t *sai_ip_addr;
    switch_nhop_key_t nhop_key;
    sai_next_hop_type_t nhtype = SAI_NEXT_HOP_IP;

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s",
                       sai_status_to_string(status));
        return status;
    }

    memset(&nhop_key, 0, sizeof(switch_nhop_key_t));
    for (index = 0; index < attr_count; index++) {
        attribute = &attr_list[index];
        switch (attribute->id) {
            case SAI_NEXT_HOP_ATTR_TYPE:
                nhtype = attribute->value.u8;
                break;
            case SAI_NEXT_HOP_ATTR_IP:
                assert(nhtype == SAI_NEXT_HOP_IP);
                sai_ip_addr = &attribute->value.ipaddr;
                sai_ip_addr_to_switch_ip_addr(sai_ip_addr, &nhop_key.ip_addr);
                nhop_key.ip_addr_valid = 1;
                break;
            case SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID:
                 SAI_ASSERT(sai_object_type_query(attribute->value.oid) ==
                            SAI_OBJECT_TYPE_ROUTER_INTERFACE);
                nhop_key.intf_handle = (switch_handle_t) attribute->value.oid;
                break;
            default:
                return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    *next_hop_id = (sai_object_id_t) switch_api_nhop_create(device, &nhop_key);
    status = (*next_hop_id == SWITCH_API_INVALID_HANDLE) ?
             SAI_STATUS_FAILURE :
             SAI_STATUS_SUCCESS;

    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to create nexthop: %s",
                      sai_status_to_string(status));
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Remove next hop
*
* Arguments:
*    [in] next_hop_id - next hop id
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_remove_next_hop_entry(
        _In_ sai_object_id_t next_hop_id) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;

    SAI_ASSERT(sai_object_type_query(next_hop_id) == SAI_OBJECT_TYPE_NEXT_HOP);

    switch_status = switch_api_nhop_delete(device, (switch_handle_t) next_hop_id);
    status = sai_switch_status_to_sai_status(switch_status);

    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to remove nexthop %lx: %s",
                      next_hop_id,
                      sai_status_to_string(status));
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Set Next Hop attribute
*
* Arguments:
*    [in] next_hop_id - next hop id
*    [in] attr - attribute
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_set_next_hop_entry_attribute(
        _In_ sai_object_id_t next_hop_id,
        _In_ const sai_attribute_t *attr) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;

    if (!attr) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute: %s",
                       sai_status_to_string(status));
        return status;
    }

    SAI_ASSERT(sai_object_type_query(next_hop_id) == SAI_OBJECT_TYPE_NEXT_HOP);

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Get Next Hop attribute
*
* Arguments:
*    [in] next_hop_id - next hop id
*    [in] attr_count - number of attributes
*    [inout] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_get_next_hop_entry_attribute(
        _In_ sai_object_id_t next_hop_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s",
                       sai_status_to_string(status));
        return status;
    }

    SAI_ASSERT(sai_object_type_query(next_hop_id) == SAI_OBJECT_TYPE_NEXT_HOP);

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
*  Next Hop methods table retrieved with sai_api_query()
*/
sai_next_hop_api_t nhop_api = {
    .create_next_hop                        =             sai_create_next_hop_entry,
    .remove_next_hop                        =             sai_remove_next_hop_entry,
    .set_next_hop_attribute                 =             sai_set_next_hop_entry_attribute,
    .get_next_hop_attribute                 =             sai_get_next_hop_entry_attribute
};

sai_status_t sai_next_hop_initialize(sai_api_service_t *sai_api_service) {
    SAI_LOG_DEBUG("Initializing nexthop");
    sai_api_service->nhop_api = nhop_api;
    return SAI_STATUS_SUCCESS;
}
