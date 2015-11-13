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

#include <saivlan.h>
#include "saiinternal.h"
#include <switchapi/switch_vlan.h>

static sai_api_t api_id = SAI_API_VLAN;

/*
* Routine Description:
*    Create a VLAN
*
* Arguments:
*    [in] vlan_id - VLAN id
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_create_vlan_entry(
        _In_ sai_vlan_id_t vlan_id) {

    SAI_LOG_ENTER();

    switch_handle_t vlan_handle = SWITCH_API_INVALID_HANDLE;

    sai_status_t status = SAI_STATUS_SUCCESS;
    vlan_handle = switch_api_vlan_create(device, (switch_vlan_t) vlan_id);

    status = (vlan_handle == SWITCH_API_INVALID_HANDLE) ?
              SAI_STATUS_FAILURE :
              SAI_STATUS_SUCCESS;

    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to create vlan %d: %s",
                      vlan_id, sai_status_to_string(status));
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Remove a VLAN
*
* Arguments:
*    [in] vlan_id - VLAN id
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_remove_vlan_entry(
        _In_ sai_vlan_id_t vlan_id) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    switch_handle_t vlan_handle = 0;

    switch_status = switch_api_vlan_id_to_handle_get((switch_vlan_t) vlan_id,
                                                     &vlan_handle);
    status = sai_switch_status_to_sai_status(switch_status);
    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to remove vlan %d: %s",
                      vlan_id, sai_status_to_string(status));
        return status;
    }

    switch_status = switch_api_vlan_delete(device, vlan_handle);
    status = sai_switch_status_to_sai_status(switch_status);
    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to remove vlan %d: %s",
                      vlan_id, sai_status_to_string(status));
        return status;
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Set VLAN attribute Value
*
* Arguments:
*    [in] vlan_id - VLAN id
*    [in] attr - attribute
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_set_vlan_entry_attribute(
        _In_ sai_vlan_id_t vlan_id,
        _In_ const sai_attribute_t *attr) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;

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
*    Get VLAN attribute Value
*
* Arguments:
*    [in] vlan_id - VLAN id
*    [in] attr_count - number of attributes
*    [inout] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_get_vlan_entry_attribute(
        _In_ sai_vlan_id_t vlan_id,
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
*    Remove VLAN configuration (remove all VLANs).
*
* Arguments:
*    None
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_remove_all_vlans(void) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Add Port to VLAN
*
* Arguments:
*    [in] vlan_id - VLAN id
*    [in] port_count - number of ports
*    [in] port_list - pointer to membership structures
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_add_ports_to_vlan(
        _In_ sai_vlan_id_t vlan_id,
        _In_ uint32_t port_count,
        _In_ const sai_vlan_port_t* port_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    switch_handle_t vlan_handle = 0;
    switch_vlan_port_t *switch_port_list;
    uint32_t index = 0;

    if (!port_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null port list: %s",
                      sai_status_to_string(status));
        return status;
    }

    switch_status = switch_api_vlan_id_to_handle_get((switch_vlan_t) vlan_id, &vlan_handle);
    status = sai_switch_status_to_sai_status(switch_status);
    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to add ports to vlan %d: %s",
                      vlan_id, sai_status_to_string(status));
        return status;
    }

    switch_port_list = (switch_vlan_port_t *) SAI_MALLOC(sizeof(switch_vlan_port_t) * port_count);
    if (!switch_port_list) {
        status = SAI_STATUS_NO_MEMORY;
        SAI_LOG_ERROR("failed to add ports to vlan %d: %s",
                      vlan_id, sai_status_to_string(status));
        return status;
    }

    for (index = 0; index < port_count; index++) {
        switch_port_list[index].handle = (switch_handle_t) port_list[index].port_id;
        switch_port_list[index].tagging_mode = (switch_vlan_tagging_mode_t) port_list[index].tagging_mode;
    }
    switch_status = switch_api_vlan_ports_add(device, vlan_handle, port_count, switch_port_list);
    status = sai_switch_status_to_sai_status(switch_status);
    if (status != SAI_STATUS_SUCCESS) {
        SAI_FREE(switch_port_list);
        SAI_LOG_ERROR("failed to add ports to vlan %d: %s",
                      vlan_id, sai_status_to_string(status));
        return status;
    }

    SAI_FREE(switch_port_list);

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*    Remove Port from VLAN
*
* Arguments:
*    [in] vlan_id - VLAN id
*    [in] port_count - number of ports
*    [in] port_list - pointer to membership structures
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_remove_ports_from_vlan(
        _In_ sai_vlan_id_t vlan_id,
        _In_ uint32_t port_count,
        _In_ const sai_vlan_port_t* port_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    switch_handle_t vlan_handle = 0;
    switch_vlan_port_t *switch_port_list;
    uint32_t index = 0;

    if (!port_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null port list: %s",
                      sai_status_to_string(status));
        return status;
    }

    switch_status = switch_api_vlan_id_to_handle_get((switch_vlan_t) vlan_id, &vlan_handle);
    status = sai_switch_status_to_sai_status(switch_status);
    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to rremove ports from vlan %d: %s",
                      vlan_id, sai_status_to_string(status));
        return status;
    }

    switch_port_list = (switch_vlan_port_t *) SAI_MALLOC(sizeof(switch_vlan_port_t) * port_count);
    if (!switch_port_list) {
        status = SAI_STATUS_NO_MEMORY;
        SAI_LOG_ERROR("failed to remove ports from vlan %d: %s",
                      vlan_id, sai_status_to_string(status));
        return status;
    }

    for (index = 0; index < port_count; index++) {
        switch_port_list[index].handle = (switch_handle_t) port_list[index].port_id;
        switch_port_list[index].tagging_mode = (switch_vlan_tagging_mode_t) port_list[index].tagging_mode;
    }

    switch_status = switch_api_vlan_ports_remove(device, vlan_handle, port_count, switch_port_list);
    status = sai_switch_status_to_sai_status(switch_status);
    if (status != SAI_STATUS_SUCCESS) {
        SAI_FREE(switch_port_list);
        SAI_LOG_ERROR("failed to add ports to vlan %d: %s",
                      vlan_id, sai_status_to_string(status));
        return status;
    }

    SAI_FREE(switch_port_list);

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* Routine Description:
*   Get vlan statistics counters.
*
* Arguments:
*    [in] vlan_id - VLAN id
*    [in] counter_ids - specifies the array of counter ids
*    [in] number_of_counters - number of counters in the array
*    [out] counters - array of resulting counter values.
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/ 
sai_status_t sai_get_vlan_stats(
        _In_ sai_vlan_id_t vlan_id, 
        _In_ const sai_vlan_stat_counter_t *counter_ids,
        _In_ uint32_t number_of_counters,
        _Out_ uint64_t* counters) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
* VLAN methods table retrieved with sai_api_query()
*/
sai_vlan_api_t vlan_api = {
    .create_vlan                       =             sai_create_vlan_entry,
    .remove_vlan                       =             sai_remove_vlan_entry,
    .set_vlan_attribute                =             sai_set_vlan_entry_attribute,
    .get_vlan_attribute                =             sai_get_vlan_entry_attribute,
    .add_ports_to_vlan                 =             sai_add_ports_to_vlan,
    .remove_ports_from_vlan            =             sai_remove_ports_from_vlan,
    .remove_all_vlans                  =             sai_remove_all_vlans,
    .get_vlan_stats                    =             sai_get_vlan_stats
};

sai_status_t sai_vlan_initialize(sai_api_service_t *sai_api_service) {
    sai_api_service->vlan_api = vlan_api;
    return SAI_STATUS_SUCCESS;
}
