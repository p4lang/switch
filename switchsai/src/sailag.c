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

sai_status_t sai_create_lag_entry(_Out_ sai_object_id_t *lag_id,
                                  _In_ uint32_t attr_count,
                                  _In_ const sai_attribute_t *attr_list);

sai_status_t sai_remove_lag_entry(_In_ sai_object_id_t lag_id);

sai_status_t sai_set_lag_entry_attribute(_In_ sai_object_id_t lag_id,
                                         _In_ const sai_attribute_t *attr);

sai_status_t sai_add_ports_to_lag(_In_ sai_object_id_t lag_id,
                                  _In_ const sai_object_list_t *port_list);

/*
    \brief Create LAG
    \param[out] lag_id LAG id
    \param[in] attr_count number of attributes
    \param[in] attr_list array of attributes
    \return Success: SAI_STATUS_SUCCESS
            Failure: Failure status code on error
*/
sai_status_t sai_create_lag_entry(_Out_ sai_object_id_t *lag_id,
                                  _In_ uint32_t attr_count,
                                  _In_ const sai_attribute_t *attr_list) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  if (attr_count && !attr_list) {
    status = SAI_STATUS_INVALID_PARAMETER;
    SAI_LOG_ERROR("null attribute list: %s", sai_status_to_string(status));
    return status;
  }

  *lag_id = (sai_object_id_t)switch_api_lag_create(device);
  status = (*lag_id == SWITCH_API_INVALID_HANDLE) ? SAI_STATUS_FAILURE
                                                  : SAI_STATUS_SUCCESS;

  if (status != SAI_STATUS_SUCCESS) {
    SAI_LOG_ERROR("failed to create lag: %s", sai_status_to_string(status));
    return status;
  }

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/*
    \brief Remove LAG
    \param[in] lag_id LAG id
    \return Success: SAI_STATUS_SUCCESS
            Failure: Failure status code on error
*/
sai_status_t sai_remove_lag_entry(_In_ sai_object_id_t lag_id) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(lag_id) == SAI_OBJECT_TYPE_LAG);

  switch_status = switch_api_lag_delete(device, (switch_handle_t)lag_id);
  status = sai_switch_status_to_sai_status(switch_status);

  if (status != SAI_STATUS_SUCCESS) {
    SAI_LOG_ERROR(
        "failed to remove lag %lx: %s", lag_id, sai_status_to_string(status));
  }
  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/*
    \brief Set LAG Attribute
    \param[in] lag_id LAG id
    \param[in] attr Structure containing ID and value to be set
    \return Success: SAI_STATUS_SUCCESS
            Failure: Failure status code on error
*/
sai_status_t sai_set_lag_attribute(_In_ sai_object_id_t lag_id,
                                   _In_ const sai_attribute_t *attr) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  if (!attr) {
    status = SAI_STATUS_INVALID_PARAMETER;
    SAI_LOG_ERROR("null attribute: %s", sai_status_to_string(status));
    return status;
  }

  SAI_ASSERT(sai_object_type_query(lag_id) == SAI_OBJECT_TYPE_LAG);

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/*
    \brief Get LAG Attribute
    \param[in] lag_id LAG id
    \param[in] attr_count Number of attributes to be get
    \param[in,out] attr_list List of structures containing ID and value to be
   get
    \return Success: SAI_STATUS_SUCCESS
            Failure: Failure status code on error
*/
sai_status_t sai_get_lag_attribute(_In_ sai_object_id_t lag_id,
                                   _In_ uint32_t attr_count,
                                   _Inout_ sai_attribute_t *attr_list) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  if (!attr_list) {
    status = SAI_STATUS_INVALID_PARAMETER;
    SAI_LOG_ERROR("null attribute list: %s", sai_status_to_string(status));
    return status;
  }

  SAI_ASSERT(sai_object_type_query(lag_id) == SAI_OBJECT_TYPE_LAG);

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

sai_status_t sai_lag_member_entry_parse(_In_ const sai_attribute_t *attr_list,
                                        _In_ uint32_t attr_count,
                                        _Out_ sai_object_id_t *lag_id,
                                        _Out_ sai_object_id_t *port_id) {
  const sai_attribute_t *attribute;
  uint32_t index = 0;

  for (index = 0; index < attr_count; index++) {
    attribute = &attr_list[index];
    switch (attribute->id) {
      case SAI_LAG_MEMBER_ATTR_LAG_ID:
        *lag_id = attribute->value.oid;
        break;
      case SAI_LAG_MEMBER_ATTR_PORT_ID:
        *port_id = attribute->value.oid;
        break;
      case SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE:
        break;
      case SAI_LAG_MEMBER_ATTR_INGRESS_DISABLE:
        break;
    }
  }
  return SAI_STATUS_SUCCESS;
}

/*
    \brief Create LAG Member
    \param[out] lag_member_id LAG Member id
    \param[in] attr_count number of attributes
    \param[in] attr_list array of attributes
    \return Success: SAI_STATUS_SUCCESS
            Failure: Failure status code on error
*/
sai_status_t sai_create_lag_member(_Out_ sai_object_id_t *lag_member_id,
                                   _In_ uint32_t attr_count,
                                   _In_ const sai_attribute_t *attr_list) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_direction_t direction = SWITCH_API_DIRECTION_BOTH;
  sai_object_id_t lag_id = 0;
  sai_object_id_t port_id = 0;

  if (!attr_list) {
    status = SAI_STATUS_INVALID_PARAMETER;
    SAI_LOG_ERROR("null port list: %s", sai_status_to_string(status));
    return status;
  }

  status = sai_lag_member_entry_parse(attr_list, attr_count, &lag_id, &port_id);
  if (status != SAI_STATUS_SUCCESS) {
    SAI_LOG_ERROR("failed to parse lag member attributes: %s",
                  sai_status_to_string(status));
    return status;
  }

  SAI_ASSERT(sai_object_type_query(lag_id) == SAI_OBJECT_TYPE_LAG);
  SAI_ASSERT(sai_object_type_query(port_id) == SAI_OBJECT_TYPE_PORT);

  *lag_member_id = switch_api_lag_member_create(
      device, (switch_handle_t)lag_id, direction, port_id);
  status = (*lag_member_id == SWITCH_API_INVALID_HANDLE) ? SAI_STATUS_FAILURE
                                                         : SAI_STATUS_SUCCESS;

  if (status != SAI_STATUS_SUCCESS) {
    SAI_LOG_ERROR("failed to create lag: %s", sai_status_to_string(status));
    return status;
  }

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/*
    \brief Remove LAG Member
    \param[in] lag_member_id LAG Member id
    \return Success: SAI_STATUS_SUCCESS
            Failure: Failure status code on error
*/
sai_status_t sai_remove_lag_member(_In_ sai_object_id_t lag_member_id) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(lag_member_id) ==
             SAI_OBJECT_TYPE_LAG_MEMBER);

  switch_status =
      switch_api_lag_member_remove(device, (switch_handle_t)lag_member_id);
  status = sai_switch_status_to_sai_status(switch_status);
  if (status != SAI_STATUS_SUCCESS) {
    SAI_LOG_ERROR("failed to remove lag member %lx : %s",
                  lag_member_id,
                  sai_status_to_string(status));
  }

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/*
    \brief Set LAG Member Attribute
    \param[in] lag_member_id LAG Member id
    \param[in] attr Structure containing ID and value to be set
    \return Success: SAI_STATUS_SUCCESS
            Failure: Failure status code on error
*/
sai_status_t sai_set_lag_member_attribute(_In_ sai_object_id_t lag_member_id,
                                          _In_ const sai_attribute_t *attr) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/*
    \brief Get LAG Member Attribute
    \param[in] lag_member_id LAG Member id
    \param[in] attr_count Number of attributes to be get
    \param[in,out] attr_list List of structures containing ID and value to be
   get
    \return Success: SAI_STATUS_SUCCESS
            Failure: Failure status code on error
*/

sai_status_t sai_get_lag_member_attribute(_In_ sai_object_id_t lag_member_id,
                                          _In_ uint32_t attr_count,
                                          _Inout_ sai_attribute_t *attr_list) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/*
*  LAG methods table retrieved with sai_api_query()
*/
sai_lag_api_t lag_api = {
    .create_lag = sai_create_lag_entry,
    .remove_lag = sai_remove_lag_entry,
    .set_lag_attribute = sai_set_lag_attribute,
    .get_lag_attribute = sai_get_lag_attribute,
    .create_lag_member = sai_create_lag_member,
    .remove_lag_member = sai_remove_lag_member,
    .set_lag_member_attribute = sai_set_lag_member_attribute,
    .get_lag_member_attribute = sai_get_lag_member_attribute,
};

sai_status_t sai_lag_initialize(sai_api_service_t *sai_api_service) {
  SAI_LOG_DEBUG("Initializing lag");
  sai_api_service->lag_api = lag_api;
  return SAI_STATUS_SUCCESS;
}
