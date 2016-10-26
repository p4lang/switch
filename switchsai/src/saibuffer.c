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

#include <saibuffer.h>
#include "saiinternal.h"
#include <switchapi/switch_buffer.h>

static sai_api_t api_id = SAI_API_BUFFERS;

/**
 * @brief Set ingress priority group attribute
 * @param[in] ingress_pg_id ingress priority group id
 * @param[in] attr attribute to set
 *
 * @return  SAI_STATUS_SUCCESS on success
 *           Failure status code on error
 */
sai_status_t sai_set_ingress_priority_group_attribute(
    _In_ sai_object_id_t ingress_pg_id, _In_ const sai_attribute_t *attr) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(ingress_pg_id) ==
             SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP);
  SAI_ASSERT(sai_object_type_query(attr->value.oid) ==
             SAI_OBJECT_TYPE_BUFFER_PROFILE);

  status = switch_api_priority_group_buffer_profile_set(
      device, ingress_pg_id, attr->value.oid);
  if (status != SAI_STATUS_SUCCESS) {
    SAI_LOG_ERROR("failed to set pg buffer profile :%s",
                  sai_status_to_string(status));
  }

  SAI_LOG_EXIT();

  return status;
}

/**
 * @brief Get ingress priority group attributes
 * @param[in] ingress_pg_id ingress priority group id
 * @param[in] attr_count number of attributes
 * @param[inout] attr_list array of attributes
 *
 * @return  SAI_STATUS_SUCCESS on success
 *           Failure status code on error
 */
sai_status_t sai_get_ingress_priority_group_attribute(
    _In_ sai_object_id_t ingress_pg_id,
    _In_ uint32_t attr_count,
    _Inout_ sai_attribute_t *attr_list) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_LOG_EXIT();

  return status;
}

static void sai_buffer_pool_attribute_parse(
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list,
    switch_direction_t *direction,
    uint32_t *size) {
  const sai_attribute_t *attribute;
  uint32_t i = 0;

  for (i = 0; i < attr_count; i++) {
    attribute = &attr_list[i];
    switch (attribute->id) {
      case SAI_BUFFER_POOL_ATTR_SHARED_SIZE:
        break;
      case SAI_BUFFER_POOL_ATTR_TYPE:
        if (attribute->value.u32 == SAI_BUFFER_POOL_TYPE_INGRESS) {
          *direction = SWITCH_API_DIRECTION_INGRESS;
        } else {
          *direction = SWITCH_API_DIRECTION_EGRESS;
        }
        break;
      case SAI_BUFFER_POOL_ATTR_SIZE:
        *size = attribute->value.u32;
        break;
      case SAI_BUFFER_POOL_ATTR_TH_MODE:
        break;
      default:
        break;
    }
  }
}

/**
 * @brief Create buffer pool
 * @param[out] pool_id buffer pool id
 * @param[in] attr_count number of attributes
 * @param[in] attr_list array of attributes
 * @return SAI_STATUS_SUCCESS on success
 *           Failure status code on error
 */
sai_status_t sai_create_buffer_pool(_Out_ sai_object_id_t *pool_id,
                                    _In_ uint32_t attr_count,
                                    _In_ const sai_attribute_t *attr_list) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_direction_t direction = 0;
  uint32_t size = 0;

  sai_buffer_pool_attribute_parse(attr_count, attr_list, &direction, &size);

  *pool_id = switch_api_buffer_pool_create(device, direction, size);

  status = (*pool_id == SWITCH_API_INVALID_HANDLE) ? SAI_STATUS_FAILURE
                                                   : SAI_STATUS_SUCCESS;

  if (status != SAI_STATUS_SUCCESS) {
    SAI_LOG_ERROR("failed to create buffer pool: %s",
                  sai_status_to_string(status));
  }

  SAI_LOG_EXIT();

  return status;
}

/**
 * @brief Remove buffer pool
 * @param[in] pool_id buffer pool id
 * @return SAI_STATUS_SUCCESS on success
 *           Failure status code on error
 */
sai_status_t sai_remove_buffer_pool(_In_ sai_object_id_t pool_id) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(pool_id) == SAI_OBJECT_TYPE_BUFFER_POOL);

  status = switch_api_buffer_pool_delete(device, pool_id);
  if (status != SAI_STATUS_SUCCESS) {
    SAI_LOG_ERROR("failed to delete buffer pool: %s",
                  sai_status_to_string(status));
  }

  SAI_LOG_EXIT();

  return status;
}

/**
 * @brief Set buffer pool attribute
 * @param[in] pool_id buffer pool id
 * @param[in] attr attribute
 * @return SAI_STATUS_SUCCESS on success
 *           Failure status code on error
 */
sai_status_t sai_set_buffer_pool_attribute(_In_ sai_object_id_t pool_id,
                                           _In_ const sai_attribute_t *attr) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(pool_id) == SAI_OBJECT_TYPE_BUFFER_POOL);

  SAI_LOG_EXIT();

  return status;
}

/**
 * @brief Get buffer pool attributes
 * @param[in] pool_id buffer pool id
 * @param[in] attr_count number of attributes
 * @param[inout] attr_list array of attributes
 * @return SAI_STATUS_SUCCESS on success
 *           Failure status code on error
 */
sai_status_t sai_get_buffer_pool_attribute(_In_ sai_object_id_t pool_id,
                                           _In_ uint32_t attr_count,
                                           _Inout_ sai_attribute_t *attr_list) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(pool_id) == SAI_OBJECT_TYPE_BUFFER_POOL);

  SAI_LOG_EXIT();

  return status;
}

static void sai_buffer_profile_attribute_parse(
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list,
    switch_api_buffer_profile_t *buffer_profile_info) {
  const sai_attribute_t *attribute;
  uint32_t i = 0;
  sai_buffer_profile_threshold_mode_t threshold_mode;

  for (i = 0; i < attr_count; i++) {
    attribute = &attr_list[i];
    switch (attribute->id) {
      case SAI_BUFFER_PROFILE_ATTR_POOL_ID:
        buffer_profile_info->pool_handle = attribute->value.oid;
        break;
      case SAI_BUFFER_PROFILE_ATTR_BUFFER_SIZE:
        buffer_profile_info->buffer_size = attribute->value.u32;
        break;
      /*
      case SAI_BUFFER_PROFILE_ATTR_TH_MODE:
          threshold_mode = attribute->value.u32;
          break;
     */
      case SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH:
        SAI_ASSERT(threshold_mode == SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC);
        buffer_profile_info->threshold_mode =
            SWITCH_BUFFER_THRESHOLD_MODE_DYNAMIC;
        buffer_profile_info->threshold = attribute->value.u32;
        break;
      case SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH:
        SAI_ASSERT(threshold_mode == SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC);
        buffer_profile_info->threshold_mode =
            SWITCH_BUFFER_THRESHOLD_MODE_STATIC;
        buffer_profile_info->threshold = attribute->value.u32;
        break;
      case SAI_BUFFER_PROFILE_ATTR_XOFF_TH:
        buffer_profile_info->xoff_threshold = attribute->value.u32;
        break;
      case SAI_BUFFER_PROFILE_ATTR_XON_TH:
        buffer_profile_info->xon_threshold = attribute->value.u32;
        break;
      default:
        break;
    }
  }
}

/**
 * @brief Create buffer profile
 * @param[out] buffer_profile_id buffer profile id
 * @param[in] attr_count number of attributes
 * @param[in] attr_list array of attributes
 * @return SAI_STATUS_SUCCESS on success
 *           Failure status code on error
 */
sai_status_t sai_create_buffer_profile(_Out_ sai_object_id_t *buffer_profile_id,
                                       _In_ uint32_t attr_count,
                                       _In_ const sai_attribute_t *attr_list) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_api_buffer_profile_t buffer_profile_info;

  memset(&buffer_profile_info, 0x0, sizeof(buffer_profile_info));

  sai_buffer_profile_attribute_parse(
      attr_count, attr_list, &buffer_profile_info);
  *buffer_profile_id =
      switch_api_buffer_profile_create(device, &buffer_profile_info);

  status = (*buffer_profile_id == SWITCH_API_INVALID_HANDLE)
               ? SAI_STATUS_FAILURE
               : SAI_STATUS_SUCCESS;

  if (status != SAI_STATUS_SUCCESS) {
    SAI_LOG_ERROR("failed to create buffer pool: %s",
                  sai_status_to_string(status));
  }

  SAI_LOG_EXIT();

  return status;
}

/**
 * @brief Remove buffer profile
 * @param[in] buffer_profile_id buffer profile id
 * @return SAI_STATUS_SUCCESS on success
 *           Failure status code on error
 */
sai_status_t sai_remove_buffer_profile(_In_ sai_object_id_t buffer_profile_id) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(buffer_profile_id) ==
             SAI_OBJECT_TYPE_BUFFER_PROFILE);

  status = switch_api_buffer_profile_delete(device, buffer_profile_id);
  if (status != SAI_STATUS_SUCCESS) {
    SAI_LOG_ERROR("failed to remove buffer pool: %s",
                  sai_status_to_string(status));
  }

  SAI_LOG_EXIT();

  return status;
}

/**
 * @brief Set buffer profile attribute
 * @param[in] buffer_profile_id buffer profile id
 * @param[in] attr attribute
 * @return SAI_STATUS_SUCCESS on success
 *           Failure status code on error
 */
sai_status_t sai_set_buffer_profile_attribute(
    _In_ sai_object_id_t buffer_profile_id, _In_ const sai_attribute_t *attr) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(buffer_profile_id) ==
             SAI_OBJECT_TYPE_BUFFER_PROFILE);

  SAI_LOG_EXIT();

  return status;
}

/**
 * @brief Get buffer profile attributes
 * @param[in] buffer_profile_id buffer profile id
 * @param[in] attr_count number of attributes
 * @param[inout] attr_list array of attributes
 * @return SAI_STATUS_SUCCESS on success
 *           Failure status code on error
 */
sai_status_t sai_get_buffer_profile_attribute(
    _In_ sai_object_id_t buffer_profile_id,
    _In_ uint32_t attr_count,
    _Inout_ sai_attribute_t *attr_list) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(buffer_profile_id) ==
             SAI_OBJECT_TYPE_BUFFER_PROFILE);

  SAI_LOG_EXIT();

  return status;
}

/*
*  Buffer methods table retrieved with sai_api_query()
*/
sai_buffer_api_t buffer_api = {
    .create_buffer_pool = sai_create_buffer_pool,
    .remove_buffer_pool = sai_remove_buffer_pool,
    .set_buffer_pool_attr = sai_set_buffer_pool_attribute,
    .get_buffer_pool_attr = sai_get_buffer_pool_attribute,
    .set_ingress_priority_group_attr = sai_set_ingress_priority_group_attribute,
    .get_ingress_priority_group_attr = sai_get_ingress_priority_group_attribute,
    .create_buffer_profile = sai_create_buffer_profile,
    .remove_buffer_profile = sai_remove_buffer_profile,
    .set_buffer_profile_attr = sai_set_buffer_profile_attribute,
    .get_buffer_profile_attr = sai_get_buffer_profile_attribute};

sai_status_t sai_buffer_initialize(sai_api_service_t *sai_api_service) {
  SAI_LOG_DEBUG("Initializing buffer");
  sai_api_service->buffer_api = buffer_api;
  return SAI_STATUS_SUCCESS;
}
