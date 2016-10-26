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

#include <saischedulergroup.h>
#include "saiinternal.h"

static sai_api_t api_id = SAI_API_SCHEDULER_GROUP;

static void sai_scheduler_group_attribute_parse(
    _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list) {
  const sai_attribute_t *attribute;
  uint32_t i = 0;

  for (i = 0; i < attr_count; i++) {
    attribute = &attr_list[i];
    switch (attribute->id) {
      case SAI_SCHEDULER_GROUP_ATTR_CHILD_COUNT:
        break;
      case SAI_SCHEDULER_GROUP_ATTR_CHILD_LIST:
        break;
      case SAI_SCHEDULER_GROUP_ATTR_PORT_ID:
        break;
      case SAI_SCHEDULER_GROUP_ATTR_LEVEL:
        break;
      case SAI_SCHEDULER_GROUP_ATTR_SCHEDULER_PROFILE_ID:
        break;
    }
  }
}

/**
 * @brief  Create Scheduler group
 *
 * @param[out] scheduler_group_id Scheudler group id
 * @param[in] attr_count number of attributes
 * @param[in] attr_list array of attributes
 *
 * @return  SAI_STATUS_SUCCESS on success
 *          Failure status code on error
 */
sai_status_t sai_create_scheduler_group(
    _Out_ sai_object_id_t *scheduler_group_id,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  sai_scheduler_group_attribute_parse(attr_count, attr_list);

  status = (*scheduler_group_id == SWITCH_API_INVALID_HANDLE)
               ? SAI_STATUS_FAILURE
               : SAI_STATUS_SUCCESS;

  if (status != SAI_STATUS_SUCCESS) {
    SAI_LOG_ERROR("failed to create scheduler group: %s",
                  sai_status_to_string(status));
  }

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/**
 * @brief  Remove Scheduler group
 *
 * @param[in] scheduler_group_id Scheudler group id
 *
 * @return  SAI_STATUS_SUCCESS on success
 *          Failure status code on error
 */
sai_status_t sai_remove_scheduler_group(_In_ sai_object_id_t
                                            scheduler_group_id) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(scheduler_group_id) ==
             SAI_OBJECT_TYPE_SCHEDULER_GROUP);

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}
/**
 * @brief  Set Scheduler group Attribute
 *
 * @param[in] scheduler_group_id Scheudler group id
 * @param[in] attr attribute to set
 *
 * @return  SAI_STATUS_SUCCESS on success
 *          Failure status code on error
 */
sai_status_t sai_set_scheduler_group_attribute(
    _In_ sai_object_id_t scheduler_group_id, _In_ const sai_attribute_t *attr) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(scheduler_group_id) ==
             SAI_OBJECT_TYPE_SCHEDULER_GROUP);

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}
/**
 * @brief  Get Scheduler Group attribute
 *
 * @param[in] scheduler_group_id - scheduler group id
 * @param[in] attr_count - number of attributes
 * @param[inout] attr_list - array of attributes
 *
 * @return SAI_STATUS_SUCCESS on success
 *        Failure status code on error
 */

sai_status_t sai_get_scheduler_group_attribute(
    _In_ sai_object_id_t scheduler_group_id,
    _In_ uint32_t attr_count,
    _Inout_ sai_attribute_t *attr_list) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(scheduler_group_id) ==
             SAI_OBJECT_TYPE_SCHEDULER_GROUP);

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/*
*  Scheduler Group methods table retrieved with sai_api_query()
*/
sai_scheduler_group_api_t scheduler_group_api = {
    .create_scheduler_group = sai_create_scheduler_group,
    .remove_scheduler_group = sai_remove_scheduler_group,
    .set_scheduler_group_attribute = sai_set_scheduler_group_attribute,
    .get_scheduler_group_attribute = sai_get_scheduler_group_attribute,
};

sai_status_t sai_scheduler_group_initialize(
    sai_api_service_t *sai_api_service) {
  SAI_LOG_DEBUG("Initializing scheulder group");
  sai_api_service->scheduler_group_api = scheduler_group_api;
  return SAI_STATUS_SUCCESS;
}
