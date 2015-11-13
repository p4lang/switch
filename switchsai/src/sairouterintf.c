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

#include <sairouterintf.h>
#include "saiinternal.h"
#include <switchapi/switch_interface.h>

static sai_api_t api_id = SAI_API_ROUTER_INTERFACE;

/*
* Routine Description:
*    Create router interface. 
*
* Arguments:
*    [out] rif_id - router interface id
*    [in] attr_count - number of attributes
*    [in] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_create_router_interface(
        _Out_ sai_object_id_t* rif_id,
        _In_ uint32_t attr_count,
        _In_ sai_attribute_t *attr_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_api_interface_info_t intf_info;
    const sai_attribute_t *attribute;
    sai_router_interface_type_t sai_intf_type;
    uint32_t index = 0;

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s",
                       sai_status_to_string(status));
        return status;
    }

    memset(&intf_info, 0, sizeof(switch_api_interface_info_t));
    intf_info.ipv4_unicast_enabled = 1;
    for (index = 0; index < attr_count; index++) {
        attribute = &attr_list[index];
        switch (attribute->id) {
            case SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID:
                SAI_ASSERT(sai_object_type_query(attribute->value.oid) ==
                           SAI_OBJECT_TYPE_VIRTUAL_ROUTER);
                intf_info.vrf_handle = (switch_handle_t) attribute->value.oid;
                break;
            case SAI_ROUTER_INTERFACE_ATTR_TYPE:
                sai_intf_type = attribute->value.u8;
                break;
            case SAI_ROUTER_INTERFACE_ATTR_PORT_ID:
                SAI_ASSERT(sai_intf_type == SAI_ROUTER_INTERFACE_TYPE_PORT);
                intf_info.type = SWITCH_API_INTERFACE_L3;
                intf_info.u.port_lag_handle = attribute->value.oid;
                break;
            case SAI_ROUTER_INTERFACE_ATTR_VLAN_ID:
                SAI_ASSERT(sai_intf_type == SAI_ROUTER_INTERFACE_TYPE_VLAN);
                intf_info.type = SWITCH_API_INTERFACE_L3_VLAN;
                intf_info.u.vlan_id = attribute->value.u16;
                break;
            case SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS:
                intf_info.mac_valid = TRUE;
                memcpy(&intf_info.mac, &attribute->value.mac, 6);
                break;
            case SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE:
                intf_info.ipv4_unicast_enabled = attribute->value.booldata;
                break;
            case SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE:
                intf_info.ipv6_unicast_enabled = attribute->value.booldata;
                break;
            default:
                return SAI_STATUS_INVALID_PARAMETER; 
        }
    }

    *rif_id = (sai_object_id_t) switch_api_interface_create(device, &intf_info);
    status = (*rif_id == SWITCH_API_INVALID_HANDLE) ?
              SAI_STATUS_FAILURE :
              SAI_STATUS_SUCCESS;

    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to create router interface: %s",
                      sai_status_to_string(status));
    }                 

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Remove router interface
*
* Arguments:
*    [in] rif_id - router interface id
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_remove_router_interface(
        _In_ sai_object_id_t rif_id) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;

    SAI_ASSERT(sai_object_type_query(rif_id) == SAI_OBJECT_TYPE_ROUTER_INTERFACE);

    switch_status = switch_api_interface_delete(device, (switch_handle_t)rif_id);
    status = sai_switch_status_to_sai_status(switch_status);

    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to remove router interface: %s",
                      sai_status_to_string(status));
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Set router interface attribute
*
* Arguments:
*    [in] rif_id - router interface id
*    [in] attr - attribute
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_set_router_interface_attribute(
        _In_ sai_object_id_t rif_id,
        _In_ const sai_attribute_t *attr) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;

    if (!attr) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute: %s",
                       sai_status_to_string(status));
        return status;
    }

    SAI_ASSERT(sai_object_type_query(rif_id) == SAI_OBJECT_TYPE_ROUTER_INTERFACE);

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Get router interface attribute
*
* Arguments:
*    [in] rif_id - router interface id
*    [in] attr_count - number of attributes
*    [inout] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_get_router_interface_attribute(
        _In_ sai_object_id_t rif_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute: %s",
                       sai_status_to_string(status));
        return status;
    }

    SAI_ASSERT(sai_object_type_query(rif_id) == SAI_OBJECT_TYPE_ROUTER_INTERFACE);

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
*  Routing interface methods table retrieved with sai_api_query()
*/
sai_router_interface_api_t rif_api = {
    .create_router_interface                =             sai_create_router_interface,
    .remove_router_interface                =             sai_remove_router_interface,
    .set_router_interface_attribute         =             sai_set_router_interface_attribute,
    .get_router_interface_attribute         =             sai_get_router_interface_attribute,
};

sai_status_t sai_router_interface_initialize(sai_api_service_t *sai_api_service) {
    SAI_LOG_DEBUG("Initializing router interface");
    sai_api_service->rif_api = rif_api;
    return SAI_STATUS_SUCCESS;
}
