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

#include <saistp.h>
#include "saiinternal.h"
#include <switchapi/switch_stp.h>
#include <switchapi/switch_vlan.h>

static sai_api_t api_id = SAI_API_STP;

/**
 * @brief Create stp instance with default port state as forwarding.
 *
 * @param[out] stp_id stp instance id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Value of attributes
 * @return SAI_STATUS_SUCCESS if operation is successful otherwise a different
 *  error code is returned.
 */
sai_status_t sai_create_stp_entry(
        _Out_ sai_object_id_t *stp_id,
        _In_  uint32_t attr_count,
        _In_  const sai_attribute_t *attr_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    const sai_attribute_t *attribute;
    const sai_vlan_list_t *vlans;
    sai_vlan_id_t vlan_id = 0;
    uint32_t index1 = 0, index2 = 0;
    switch_handle_t *vlan_handle;

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s",
                      sai_status_to_string(status));
        return status;
    }

    *stp_id = (sai_object_id_t) switch_api_stp_group_create(device, 0);

    status = (*stp_id == SWITCH_API_INVALID_HANDLE) ?
             SAI_STATUS_FAILURE :
             SAI_STATUS_SUCCESS;

    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to create stp entry: %s",
                      sai_status_to_string(status));
        return status;
    }

    for (index1 = 0; index1 < attr_count; index1++) {
        attribute = &attr_list[index1];
        if (attribute->id == SAI_STP_ATTR_VLAN_LIST) {
            vlans = &attribute->value.vlanlist;

            vlan_handle = (switch_handle_t *) SAI_MALLOC(sizeof(switch_handle_t) * vlans->vlan_count);
            if (!vlan_handle) {
                status = SAI_STATUS_NO_MEMORY;
                SAI_LOG_ERROR("failed to create stp entry : %s",
                              sai_status_to_string(status));
                return status;
            }

            for (index2 = 0; index2 < vlans->vlan_count; index2++) {
                vlan_id = vlans->vlan_list[index2];
                switch_status = switch_api_vlan_id_to_handle_get(vlan_id,
                                                         &vlan_handle[index2]);
                status = sai_switch_status_to_sai_status(switch_status);
                if (status != SAI_STATUS_SUCCESS) {
                    SAI_FREE(vlan_handle);
                    SAI_LOG_ERROR("failed to add ports to vlan %d: %s",
                                   vlan_id, sai_status_to_string(status));
                    return status;
                }
            }
            switch_status = switch_api_stp_group_vlans_add(device, *stp_id,
                                                         vlans->vlan_count,
                                                         vlan_handle);
            status = sai_switch_status_to_sai_status(switch_status);
            SAI_FREE(vlan_handle);
            if (status != SAI_STATUS_SUCCESS) {
                SAI_LOG_ERROR("failed to add ports to vlan %d: %s",
                              vlan_id, sai_status_to_string(status));
                return status;
            }
        }
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/**
 * @brief Remove stp instance.
 *
 * @param[in] stp_id stp instance id
 * @return SAI_STATUS_SUCCESS if operation is successful otherwise a different
 *  error code is returned.
 */
sai_status_t sai_remove_stp_entry(
        _In_ sai_object_id_t stp_id) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;

    SAI_ASSERT(sai_object_type_query(stp_id) == SAI_OBJECT_TYPE_STP_INSTANCE);

    switch_status = switch_api_stp_group_delete(device, (switch_handle_t)stp_id);
    status = sai_switch_status_to_sai_status(switch_status);
    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to remove stp entry %lx: %s",
                      stp_id, sai_status_to_string(status));
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/**
 * @brief Update stp state of a port in specified stp instance.
 *
 * @param[in] stp_id stp instance id
 * @param[in] port_id port id
 * @param[in] stp_port_state stp state of the port
 * @return SAI_STATUS_SUCCESS if operation is successful otherwise a different
 *  error code is returned.
 */
sai_status_t sai_set_stp_entry_attribute(
        _In_ sai_object_id_t stp_id,
        _In_ const sai_attribute_t *attr) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;

    if (!attr) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute: %s",
                      sai_status_to_string(status));
        return status;
    }

    SAI_ASSERT(sai_object_type_query(stp_id) == SAI_OBJECT_TYPE_STP_INSTANCE);

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/**
 * @brief Retrieve stp state of a port in specified stp instance.
 *
 * @param[in] stp_id stp instance id
 * @param[in] port_id port id
 * @param[out] stp_port_state stp state of the port
 * @return SAI_STATUS_SUCCESS if operation is successful otherwise a different
 *  error code is returned.
 */
sai_status_t sai_get_stp_entry_attribute(
        _In_ sai_object_id_t stp_id,
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

    SAI_ASSERT(sai_object_type_query(stp_id) == SAI_OBJECT_TYPE_STP_INSTANCE);

    SAI_LOG_EXIT();

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Set the attribute of STP instance.
 *
 * @param[in] stp_id stp instance id
 * @param[in] attr attribute value
 * @return SAI_STATUS_SUCCESS if operation is successful otherwise a different
 *  error code is returned.
 */
sai_status_t sai_set_stp_port_state(
        _In_ sai_object_id_t stp_id,
        _In_ sai_object_id_t port_id,   
        _In_ sai_port_stp_port_state_t stp_port_state) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    switch_stp_state_t switch_stp_state = SWITCH_PORT_STP_STATE_NONE;

    SAI_ASSERT(sai_object_type_query(stp_id) == SAI_OBJECT_TYPE_STP_INSTANCE);

    switch (stp_port_state) {
        case SAI_PORT_STP_STATE_LEARNING:
            switch_stp_state = SWITCH_PORT_STP_STATE_LEARNING;
            break;
        case SAI_PORT_STP_STATE_FORWARDING:
            switch_stp_state = SWITCH_PORT_STP_STATE_FORWARDING;
            break;
        case SAI_PORT_STP_STATE_BLOCKING:
            switch_stp_state = SWITCH_PORT_STP_STATE_BLOCKING;
            break;
    }
    switch_status = switch_api_stp_port_state_set(device, stp_id,
                                                  port_id,
                                                  switch_stp_state);
    status = sai_switch_status_to_sai_status(switch_status);
    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to set stp port state %lx: %s",
                      stp_id, sai_status_to_string(status));
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/**
 * @brief Get the attribute of STP instance.
 *
 * @param[in] stp_id stp instance id
 * @param[in] attr_count number of the attribute
 * @param[in] attr_list attribute value
 * @return SAI_STATUS_SUCCESS if operation is successful otherwise a different
 *  error code is returned.
 */
sai_status_t sai_get_stp_port_state(
        _In_ sai_object_id_t stp_id,
        _In_ sai_object_id_t port_id,   
        _Out_ sai_port_stp_port_state_t *stp_port_state) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    switch_stp_state_t switch_stp_state = SWITCH_PORT_STP_STATE_NONE;

    SAI_ASSERT(sai_object_type_query(stp_id) == SAI_OBJECT_TYPE_STP_INSTANCE);

    switch_status = switch_api_stp_port_state_get(device, stp_id,
                                                  port_id,
                                                  &switch_stp_state);
    status = sai_switch_status_to_sai_status(switch_status);
    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to set stp port state %lx: %s",
                      stp_id, sai_status_to_string(status));
        return status;
    }

    switch (switch_stp_state) {
        case SWITCH_PORT_STP_STATE_LEARNING:
            *stp_port_state = SAI_PORT_STP_STATE_LEARNING;
            break;
        case SWITCH_PORT_STP_STATE_FORWARDING:
            *stp_port_state = SAI_PORT_STP_STATE_FORWARDING;
            break;
        case SWITCH_PORT_STP_STATE_BLOCKING:
            *stp_port_state = SAI_PORT_STP_STATE_BLOCKING;
            break;
        default:
            *stp_port_state = 0;
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/**
 * @brief STP method table retrieved with sai_api_query()
 */
sai_stp_api_t stp_api = {
    .create_stp                        =             sai_create_stp_entry,
    .remove_stp                        =             sai_remove_stp_entry,
    .set_stp_attribute                 =             sai_set_stp_entry_attribute,
    .get_stp_attribute                 =             sai_get_stp_entry_attribute,
    .set_stp_port_state                =             sai_set_stp_port_state,
    .get_stp_port_state                =             sai_get_stp_port_state
};

sai_status_t sai_stp_initialize(sai_api_service_t *sai_api_service) {
    SAI_LOG_DEBUG("Initializing spanning tree");
    sai_api_service->stp_api = stp_api;
    return SAI_STATUS_SUCCESS;
}
