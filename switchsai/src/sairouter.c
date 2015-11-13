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

#include <sairouter.h>
#include "saiinternal.h"
#include <switchapi/switch_vrf.h>

static sai_api_t api_id = SAI_API_VIRTUAL_ROUTER;

static void sai_vrf_entry_attribute_parse(
        uint32_t attr_count,
        const sai_attribute_t *attr_list) {

    const sai_attribute_t *attribute;
    uint32_t i = 0;

    for (i = 0; i < attr_count; i++) {
        attribute = &attr_list[i];
        switch (attribute->id) {
            case SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE:
                break;
            case SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE:
                break;
            case SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS:
                break;
            default:
                break;
        }
    }
}

/*
* Routine Description:
*    Create virtual router
*    
* Arguments:
*    [out] vr_id - virtual router id
*    [in] attr_count - number of attributes
*    [in] attr_list - array of attributes
* 
* Return Values:
*  - SAI_STATUS_SUCCESS on success
*  - SAI_STATUS_ADDR_NOT_FOUND if neither SAI_SWITCH_ATTR_SRC_MAC_ADDRESS nor 
*    SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS is set.
*/
sai_status_t sai_create_virtual_router_entry(
        _Out_ sai_object_id_t *vr_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_vrf_id_t vrf_id = 1;

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s",
                       sai_status_to_string(status));
        return status;
    }

    sai_vrf_entry_attribute_parse(attr_count, attr_list);

    *vr_id = (sai_object_id_t) switch_api_vrf_create(device, vrf_id);

    status = (*vr_id == SWITCH_API_INVALID_HANDLE) ?
             SAI_STATUS_FAILURE :
             SAI_STATUS_SUCCESS;

    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to create virtual router entry : %s",
                       sai_status_to_string(status));
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Remove virtual router
*
* Arguments:
*    [in] vr_id - virtual router id
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_remove_virtual_router_entry(
        _In_ sai_object_id_t vr_id) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;

    SAI_ASSERT(sai_object_type_query(vr_id) == SAI_OBJECT_TYPE_VIRTUAL_ROUTER);

    switch_status = switch_api_vrf_delete(device, vr_id);
    status = sai_switch_status_to_sai_status(switch_status);

    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to remove virtual router entry %lx : %s",
                       vr_id, sai_status_to_string(status));
    }

    SAI_LOG_EXIT();
    return (sai_status_t) status;
}

/*
* Routine Description:
*    Set virtual router attribute Value
*
* Arguments:
*    [in] vr_id - virtual router id
*    [in] attr - attribute
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_set_virtual_router_entry_attribute(
        _In_ sai_object_id_t vr_id,
        _In_ const sai_attribute_t *attr) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;

    if (!attr) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute: %s",
                       sai_status_to_string(status));
        return status;
    }

    SAI_ASSERT(sai_object_type_query(vr_id) == SAI_OBJECT_TYPE_VIRTUAL_ROUTER);

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Get virtual router attribute Value
*
* Arguments:
*    [in] vr_id - virtual router id
*    [in] attr_count - number of attributes
*    [in] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_get_virtual_router_entry_attribute(
        _In_ sai_object_id_t vr_id,
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

    SAI_ASSERT(sai_object_type_query(vr_id) == SAI_OBJECT_TYPE_VIRTUAL_ROUTER);

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
*  Virtual router methods table retrieved with sai_api_query()
*/
sai_virtual_router_api_t vr_api = {
    .create_virtual_router               =             sai_create_virtual_router_entry,
    .remove_virtual_router               =             sai_remove_virtual_router_entry,
    .set_virtual_router_attribute        =             sai_set_virtual_router_entry_attribute,
    .get_virtual_router_attribute        =             sai_get_virtual_router_entry_attribute
};

sai_status_t sai_virtual_router_initialize(sai_api_service_t *sai_api_service) {
    SAI_LOG_DEBUG("Initializing virtual router");
    sai_api_service->vr_api = vr_api;
    return SAI_STATUS_SUCCESS;
}
