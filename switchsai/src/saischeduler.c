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

#include <saischeduler.h>
#include "saiinternal.h"
#include <switchapi/switch_scheduler.h>

static sai_api_t api_id = SAI_API_SCHEDULER;

static void sai_scheduler_attribute_parse(
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list,
    switch_scheduler_info_t *scheduler_info) {
  const sai_attribute_t *attribute;
  uint32_t i = 0;

  for (i = 0; i < attr_count; i++) {
    attribute = &attr_list[i];
    switch (attribute->id) {
      case SAI_SCHEDULER_ATTR_SCHEDULING_ALGORITHM:
        break;
      case SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT:
        scheduler_info->weight = attribute->value.u8;
        break;
      case SAI_SCHEDULER_ATTR_SHAPER_TYPE:
        if (attribute->value.u32 == SAI_METER_TYPE_PACKETS) {
          scheduler_info->shaper_type = SWITCH_METER_TYPE_PACKETS;
        } else {
          scheduler_info->shaper_type = SWITCH_METER_TYPE_BYTES;
        }
        break;
      case SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_RATE:
        scheduler_info->min_rate = attribute->value.u64;
        break;
      case SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_BURST_RATE:
        scheduler_info->min_burst_size = attribute->value.u64;
        break;
      case SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE:
        scheduler_info->max_rate = attribute->value.u64;
        break;
      case SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_BURST_RATE:
        scheduler_info->max_burst_size = attribute->value.u64;
        break;
      default:
        break;
    }
  }
}

/**
 * @brief  Create Scheduler Profile
 *
 * @param[out] scheduler_id Scheduler id
 * @param[in] attr_count number of attributes
 * @param[in] attr_list array of attributes
 *
 * @return  SAI_STATUS_SUCCESS on success
 *          Failure status code on error
 */
sai_status_t sai_create_scheduler_profile(
    _Out_ sai_object_id_t *scheduler_id,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_scheduler_info_t scheduler_info;

  memset(&scheduler_info, 0x0, sizeof(scheduler_info));
  sai_scheduler_attribute_parse(attr_count, attr_list, &scheduler_info);

  *scheduler_id = switch_api_scheduler_create(device, &scheduler_info);

  status = (*scheduler_id == SWITCH_API_INVALID_HANDLE) ? SAI_STATUS_FAILURE
                                                        : SAI_STATUS_SUCCESS;

  if (status != SAI_STATUS_SUCCESS) {
    SAI_LOG_ERROR("failed to create scheduler: %s",
                  sai_status_to_string(status));
  }

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/**
 * @brief  Remove Scheduler profile
 *
 * @param[in] scheduler_id Scheduler id
 *
 * @return  SAI_STATUS_SUCCESS on success
 *          Failure status code on error
 */
sai_status_t sai_remove_scheduler_profile(_In_ sai_object_id_t scheduler_id) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(scheduler_id) == SAI_OBJECT_TYPE_SCHEDULER);

  status = switch_api_scheduler_delete(device, scheduler_id);
  if (status != SWITCH_STATUS_SUCCESS) {
    SAI_LOG_ERROR("failed to remove scheduler: %s",
                  sai_status_to_string(status));
  }

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/**
 * @brief  Set Scheduler Attribute
 *
 * @param[in] scheduler_id Scheduler id
 * @param[in] attr attribute to set
 *
 * @return  SAI_STATUS_SUCCESS on success
 *          Failure status code on error
 */
sai_status_t sai_set_scheduler_attribute(_In_ sai_object_id_t scheduler_id,
                                         _In_ const sai_attribute_t *attr) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(scheduler_id) == SAI_OBJECT_TYPE_SCHEDULER);

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/**
 * @brief  Get Scheduler attribute
 *
 * @param[in] scheduler_id - scheduler id
 * @param[in] attr_count - number of attributes
 * @param[inout] attr_list - array of attributes
 *
 * @return SAI_STATUS_SUCCESS on success
 *        Failure status code on error
 */

sai_status_t sai_get_scheduler_attribute(_In_ sai_object_id_t scheduler_id,
                                         _In_ uint32_t attr_count,
                                         _Inout_ sai_attribute_t *attr_list) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(scheduler_id) == SAI_OBJECT_TYPE_SCHEDULER);

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/*
*  Scheduler methods table retrieved with sai_api_query()
*/
sai_scheduler_api_t scheduler_api = {
    .create_scheduler_profile = sai_create_scheduler_profile,
    .remove_scheduler_profile = sai_remove_scheduler_profile,
    .set_scheduler_attribute = sai_set_scheduler_attribute,
    .get_scheduler_attribute = sai_get_scheduler_attribute};

sai_status_t sai_scheduler_initialize(sai_api_service_t *sai_api_service) {
  SAI_LOG_DEBUG("Initializing scheulder");
  sai_api_service->scheduler_api = scheduler_api;
  return SAI_STATUS_SUCCESS;
}
