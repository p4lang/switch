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

#include <saiqueue.h>
#include "saiinternal.h"
#include <switchapi/switch_buffer.h>

static sai_api_t api_id = SAI_API_QUEUE;

/**
 * @brief Set attribute to Queue
 * @param[in] queue_id queue id to set the attribute
 * @param[in] attr attribute to set
 *
 * @return  SAI_STATUS_SUCCESS on success
 *           Failure status code on error
 */
sai_status_t sai_set_queue_attribute(_In_ sai_object_id_t queue_id,
                                     _In_ const sai_attribute_t *attr) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(queue_id) == SAI_OBJECT_TYPE_QUEUE);

  switch (attr->id) {
    case SAI_QUEUE_ATTR_BUFFER_PROFILE_ID:
      switch_status = switch_api_queue_buffer_profile_set(
          device, queue_id, attr->value.oid);
      status = sai_switch_status_to_sai_status(switch_status);
      if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to set buffer profile for queue:%s",
                      sai_status_to_string(status));
      }
      break;
    case SAI_QUEUE_ATTR_WRED_PROFILE_ID:
    case SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID:
      status = SWITCH_STATUS_NOT_SUPPORTED;
      break;
  }

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/**
 * @brief Get attribute to Queue
 * @param[in] queue_id queue id to set the attribute
 * @param[in] attr_count number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return  SAI_STATUS_SUCCESS on success
 *           Failure status code on error
 */
sai_status_t sai_get_queue_attribute(_In_ sai_object_id_t queue_id,
                                     _In_ uint32_t attr_count,
                                     _Inout_ sai_attribute_t *attr_list) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(queue_id) == SAI_OBJECT_TYPE_QUEUE);

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/**
 * @brief   Get queue statistics counters.
 *
 * @param[in] queue_id Queue id
 * @param[in] counter_ids specifies the array of counter ids
 * @param[in] number_of_counters number of counters in the array
 * @param[out] counters array of resulting counter values.
 *
 * @return SAI_STATUS_SUCCESS on success
 *         Failure status code on error
 */
sai_status_t sai_get_queue_stats(_In_ sai_object_id_t queue_id,
                                 _In_ const sai_queue_stat_t *counter_ids,
                                 _In_ uint32_t number_of_counters,
                                 _Out_ uint64_t *counters) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(queue_id) == SAI_OBJECT_TYPE_QUEUE);

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/**
 * @brief   Clear queue statistics counters.
 *
 * @param[in] queue_id Queue id
 * @param[in] counter_ids specifies the array of counter ids
 * @param[in] number_of_counters number of counters in the array
 *
 * @return SAI_STATUS_SUCCESS on success
 *         Failure status code on error
 */
sai_status_t sai_clear_queue_stats(_In_ sai_object_id_t queue_id,
                                   _In_ const sai_queue_stat_t *counter_ids,
                                   _In_ uint32_t number_of_counters) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(queue_id) == SAI_OBJECT_TYPE_QUEUE);

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/*
*  Queue  methods table retrieved with sai_api_query()
*/
sai_queue_api_t queue_api = {.set_queue_attribute = sai_set_queue_attribute,
                             .get_queue_attribute = sai_get_queue_attribute,
                             .get_queue_stats = sai_get_queue_stats};

sai_status_t sai_queue_initialize(sai_api_service_t *sai_api_service) {
  SAI_LOG_DEBUG("Initializing queue map");
  sai_api_service->queue_api = queue_api;
  return SAI_STATUS_SUCCESS;
}
