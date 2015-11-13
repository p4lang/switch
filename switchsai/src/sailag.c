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

#include <sailag.h>
#include "saiinternal.h"
#include <switchapi/switch_lag.h>

static sai_api_t api_id = SAI_API_LAG;

sai_status_t sai_create_lag_entry(
        _Out_ sai_object_id_t* lag_id,
        _In_ uint32_t attr_count,
        _In_ sai_attribute_t *attr_list);

sai_status_t sai_remove_lag_entry(
        _In_ sai_object_id_t lag_id);

sai_status_t sai_set_lag_entry_attribute(
        _In_ sai_object_id_t lag_id,
        _In_ const sai_attribute_t *attr);

sai_status_t sai_add_ports_to_lag(
        _In_ sai_object_id_t lag_id,
        _In_ const sai_object_list_t *port_list);

/*
    \brief Create LAG
    \param[out] lag_id LAG id
    \param[in] attr_count number of attributes
    \param[in] attr_list array of attributes
    \return Success: SAI_STATUS_SUCCESS
            Failure: Failure status code on error
*/
sai_status_t sai_create_lag_entry(
        _Out_ sai_object_id_t* lag_id,
        _In_ uint32_t attr_count,
        _In_ sai_attribute_t *attr_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    sai_attribute_t attribute;
    uint32_t index = 0;

    if (!attr_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute list: %s",
                      sai_status_to_string(status));
        return status;
    }

    *lag_id = (sai_object_id_t) switch_api_lag_create(device);
    status = (*lag_id == SWITCH_API_INVALID_HANDLE) ?
             SAI_STATUS_FAILURE :
             SAI_STATUS_SUCCESS;

    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to create lag: %s",
                      sai_status_to_string(status));
        return status;
    }

    for (index = 0; index < attr_count; index++) {
        attribute = attr_list[index];
        switch (attribute.id) {
            case SAI_LAG_ATTR_PORT_LIST:
                switch_status = sai_add_ports_to_lag(
                                        *lag_id,
                                        &attr_list[index].value.objlist);
                status = sai_switch_status_to_sai_status(switch_status);
                if (status != SAI_STATUS_SUCCESS) {
                    SAI_LOG_ERROR("failed to add ports to lag %lx : %s",
                                  lag_id,
                                  sai_status_to_string(status));
                }
                break;
        }
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
    \brief Remove LAG
    \param[in] lag_id LAG id
    \return Success: SAI_STATUS_SUCCESS
            Failure: Failure status code on error
*/
sai_status_t sai_remove_lag_entry(
        _In_ sai_object_id_t lag_id) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;

    SAI_ASSERT(sai_object_type_query(lag_id) == SAI_OBJECT_TYPE_LAG);

    switch_status = switch_api_lag_delete(device, (switch_handle_t) lag_id);
    status = sai_switch_status_to_sai_status(switch_status);

    if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to remove lag %lx: %s",
                      lag_id,
                      sai_status_to_string(status));
    }
    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
    \brief Set LAG Attribute
    \param[in] lag_id LAG id
    \param[in] attr Structure containing ID and value to be set
    \return Success: SAI_STATUS_SUCCESS
            Failure: Failure status code on error
*/
sai_status_t sai_set_lag_entry_attribute(
        _In_ sai_object_id_t lag_id,
        _In_ const sai_attribute_t *attr) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;

    if (!attr) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null attribute: %s",
                      sai_status_to_string(status));
        return status;
    }

    SAI_ASSERT(sai_object_type_query(lag_id) == SAI_OBJECT_TYPE_LAG);

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
    \brief Get LAG Attribute
    \param[in] lag_id LAG id
    \param[in] attr_count Number of attributes to be get
    \param[in,out] attr_list List of structures containing ID and value to be get
    \return Success: SAI_STATUS_SUCCESS
            Failure: Failure status code on error
*/
sai_status_t sai_get_lag_entry_attribute(
        _In_ sai_object_id_t lag_id,
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

    SAI_ASSERT(sai_object_type_query(lag_id) == SAI_OBJECT_TYPE_LAG);

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
    \brief Add ports to LAG.
    \param[in] lag_id LAG id
    \param[in] port_count number of ports
    \param[in] port_list pointer to membership structures
    \return Success: SAI_STATUS_SUCCESS
            Failure: Failure status code on error
*/
sai_status_t sai_add_ports_to_lag(
        _In_ sai_object_id_t lag_id,
        _In_ const sai_object_list_t *port_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    switch_direction_t direction = SWITCH_API_DIRECTION_BOTH;
    uint32_t index = 0;

    if (!port_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null port list: %s",
                      sai_status_to_string(status));
        return status;
    }

    SAI_ASSERT(sai_object_type_query(lag_id) == SAI_OBJECT_TYPE_LAG);

    for (index = 0; index < port_list->count; index++) {
        switch_status = switch_api_lag_member_add(device,
                        (switch_handle_t) lag_id,
                        direction,
                        port_list->list[index]);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
            SAI_LOG_ERROR("failed to add port %lx to lag %lx : %s",
                          port_list->list[index], lag_id,
                          sai_status_to_string(status));
            break;
        }
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
    \brief Remove ports from LAG.
    \param[in] lag_id LAG id
    \param[in] port_count number of ports
    \param[in] port_list pointer to membership structures
    \return Success: SAI_STATUS_SUCCESS
            Failure: Failure status code on error
*/
sai_status_t sai_remove_ports_from_lag(
        _In_ sai_object_id_t lag_id,
        _In_ const sai_object_list_t *port_list) {

    SAI_LOG_ENTER();

    sai_status_t status = SAI_STATUS_SUCCESS;
    switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
    switch_direction_t direction = SWITCH_API_DIRECTION_BOTH;
    uint32_t index = 0;

    if (!port_list) {
        status = SAI_STATUS_INVALID_PARAMETER;
        SAI_LOG_ERROR("null port list: %s",
                      sai_status_to_string(status));
        return status;
    }

    SAI_ASSERT(sai_object_type_query(lag_id) == SAI_OBJECT_TYPE_LAG);

    for (index = 0; index < port_list->count; index++) {
        switch_status = switch_api_lag_member_delete(device,
                        (switch_handle_t) lag_id,
                        direction,
                        port_list->list[index]);
        status = sai_switch_status_to_sai_status(switch_status);
        if (status != SAI_STATUS_SUCCESS) {
            SAI_LOG_ERROR("failed to remove port %lx from lag %lx : %s",
                          port_list->list[index], lag_id,
                          sai_status_to_string(status));
            break;
        }
    }

    SAI_LOG_EXIT();

    return (sai_status_t) status;
}

/*
*  LAG methods table retrieved with sai_api_query()
*/
sai_lag_api_t lag_api = {
    .create_lag                        =             sai_create_lag_entry,
    .remove_lag                        =             sai_remove_lag_entry,
    .set_lag_attribute                 =             sai_set_lag_entry_attribute,
    .get_lag_attribute                 =             sai_get_lag_entry_attribute,
    .add_ports_to_lag                  =             sai_add_ports_to_lag,
    .remove_ports_from_lag             =             sai_remove_ports_from_lag,
};

sai_status_t sai_lag_initialize(sai_api_service_t *sai_api_service) {
    SAI_LOG_DEBUG("Initializing lag");
    sai_api_service->lag_api = lag_api;
    return SAI_STATUS_SUCCESS;
}
