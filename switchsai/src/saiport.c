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

#include <saiport.h>
#include "saiinternal.h"
#include <switchapi/switch_port.h>

static sai_api_t api_id = SAI_API_PORT;

/*
* Routine Description:
*   Set port attribute value.
*
* Arguments:
*    [in] port_id - port id
*    [in] attr - attribute
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_set_port_attribute(
        _In_ sai_object_id_t port_id, 
        _In_ const sai_attribute_t *attr) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    switch_handle_t vlan_handle = SWITCH_API_INVALID_HANDLE;
    switch_vlan_port_t switch_port;

    if (!attr) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute: %s",
                       sai_status_to_string(status));
        return status;
    }

    switch (attr->id) {
        case SAI_PORT_ATTR_DEFAULT_VLAN:
            switch_status = switch_api_vlan_id_to_handle_get((switch_vlan_t) attr->value.u16, &vlan_handle);
            status = sai_switch_status_to_sai_status(switch_status);
            if (status != SAI_STATUS_SUCCESS) {
                SAI_LOG_ERROR("failed to get vlan %d: %s",
                              sai_status_to_string(status));
                return status;
            }
            switch_port.handle = (switch_handle_t)port_id;
            switch_port.tagging_mode = SWITCH_VLAN_PORT_UNTAGGED;
            switch_status = switch_api_vlan_ports_add(device, vlan_handle, 1, &switch_port);
            status = sai_switch_status_to_sai_status(switch_status);
            if (status != SAI_STATUS_SUCCESS) {
                SAI_LOG_ERROR("failed to add port %d to default vlan: %s",
                              port_id, sai_status_to_string(status));
                return status;
            }
            break;
        default:
            break;
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*   Get port attribute value.
*
* Arguments:
*    [in] port_id - port id
*    [in] attr_count - number of attributes
*    [inout] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_get_port_attribute(
        _In_ sai_object_id_t port_id, 
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

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*   Get port statistics counters.
*
* Arguments:
*    [in] port_id - port id
*    [in] counter_ids - specifies the array of counter ids
*    [in] number_of_counters - number of counters in the array
*    [out] counters - array of resulting counter values.
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/ 
sai_status_t sai_get_port_stats(
        _In_ sai_object_id_t port_id, 
        _In_ const sai_port_stat_counter_t *counter_ids,
        _In_ uint32_t number_of_counters,
        _Out_ uint64_t* counters) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Port methods table retrieved with sai_api_query()
*/
sai_port_api_t port_api = {
    .set_port_attribute                =             sai_set_port_attribute,
    .get_port_attribute                =             sai_get_port_attribute,
    .get_port_stats                    =             sai_get_port_stats
};

sai_status_t sai_port_initialize(sai_api_service_t *sai_api_service) {
    SAI_LOG_DEBUG("Initializing port");
    sai_api_service->port_api = port_api;
    return SAI_STATUS_SUCCESS;
}
