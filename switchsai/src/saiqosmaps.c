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

#include <saiqosmaps.h>
#include "saiinternal.h"
#include <switchapi/switch_qos.h>

static sai_api_t api_id = SAI_API_QOS_MAPS;

static sai_status_t sai_qos_map_type_to_switch_qos_map_type(
    sai_qos_map_type_t qos_map_type,
    switch_direction_t *direction,
    switch_qos_map_ingress_t *ingress_qos_map_type,
    switch_qos_map_egress_t *egress_qos_map_type) {
  sai_status_t status = SAI_STATUS_SUCCESS;

  *ingress_qos_map_type = SWITCH_QOS_MAP_INGRESS_NONE;
  *egress_qos_map_type = SWITCH_QOS_MAP_EGRESS_NONE;

  switch (qos_map_type) {
    case SAI_QOS_MAP_TYPE_DOT1P_TO_TC:
      *ingress_qos_map_type = SWITCH_QOS_MAP_INGRESS_PCP_TO_TC;
      *direction = SWITCH_API_DIRECTION_INGRESS;
      break;
    case SAI_QOS_MAP_TYPE_DOT1P_TO_COLOR:
      *ingress_qos_map_type = SWITCH_QOS_MAP_INGRESS_PCP_TO_COLOR;
      *direction = SWITCH_API_DIRECTION_INGRESS;
      break;
    case SAI_QOS_MAP_TYPE_DSCP_TO_TC:
      *ingress_qos_map_type = SWITCH_QOS_MAP_INGRESS_DSCP_TO_TC;
      *direction = SWITCH_API_DIRECTION_INGRESS;
      break;
    case SAI_QOS_MAP_TYPE_DSCP_TO_COLOR:
      *ingress_qos_map_type = SWITCH_QOS_MAP_INGRESS_DSCP_TO_COLOR;
      *direction = SWITCH_API_DIRECTION_INGRESS;
      break;
    case SAI_QOS_MAP_TYPE_TC_TO_QUEUE:
      *ingress_qos_map_type = SWITCH_QOS_MAP_INGRESS_TC_TO_QUEUE;
      *direction = SWITCH_API_DIRECTION_INGRESS;
      break;
    case SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DSCP:
      *egress_qos_map_type = SWITCH_QOS_MAP_EGRESS_TC_AND_COLOR_TO_DSCP;
      *direction = SWITCH_API_DIRECTION_EGRESS;
      break;
    case SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DOT1P:
      *egress_qos_map_type = SWITCH_QOS_MAP_EGRESS_TC_AND_COLOR_TO_PCP;
      *direction = SWITCH_API_DIRECTION_EGRESS;
      break;
    case SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP:
    case SAI_QOS_MAP_TYPE_PFC_PRIORITY_TO_QUEUE:
    default:
      status = SAI_STATUS_NOT_SUPPORTED;
      break;
  }

  return status;
}

static switch_color_t sai_color_to_switch_color(sai_packet_color_t color) {
  switch (color) {
    case SAI_PACKET_COLOR_GREEN:
      return SWITCH_COLOR_GREEN;
    case SAI_PACKET_COLOR_YELLOW:
      return SWITCH_COLOR_YELLOW;
    case SAI_PACKET_COLOR_RED:
      return SWITCH_COLOR_RED;
    default:
      return SWITCH_COLOR_GREEN;
  }
}

static void sai_qos_map_to_switch_qos_map(sai_qos_map_type_t qos_map_type,
                                          sai_qos_map_t *qos_map,
                                          switch_qos_map_t *switch_qos_map) {
  switch (qos_map_type) {
    case SAI_QOS_MAP_TYPE_DOT1P_TO_TC:
      switch_qos_map->pcp = qos_map->key.dot1p;
      switch_qos_map->tc = qos_map->value.tc;
      break;
    case SAI_QOS_MAP_TYPE_DOT1P_TO_COLOR:
      switch_qos_map->pcp = qos_map->key.dot1p;
      switch_qos_map->color = sai_color_to_switch_color(qos_map->value.color);
      break;
    case SAI_QOS_MAP_TYPE_DSCP_TO_TC:
      switch_qos_map->dscp = qos_map->key.dscp;
      switch_qos_map->tc = qos_map->value.tc;
      break;
    case SAI_QOS_MAP_TYPE_DSCP_TO_COLOR:
      switch_qos_map->dscp = qos_map->key.dscp;
      switch_qos_map->color = sai_color_to_switch_color(qos_map->value.color);
      break;
    case SAI_QOS_MAP_TYPE_TC_TO_QUEUE:
      switch_qos_map->tc = qos_map->key.tc;
      switch_qos_map->qid = qos_map->value.queue_index;
      break;
    case SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DSCP:
      switch_qos_map->tc = qos_map->key.tc;
      switch_qos_map->color = sai_color_to_switch_color(qos_map->key.color);
      switch_qos_map->dscp = qos_map->value.dscp;
      break;
    case SAI_QOS_MAP_TYPE_TC_AND_COLOR_TO_DOT1P:
      switch_qos_map->tc = qos_map->key.tc;
      switch_qos_map->color = sai_color_to_switch_color(qos_map->key.color);
      switch_qos_map->pcp = qos_map->value.dot1p;
      break;
    default:
      break;
  }
}

static sai_status_t sai_qos_map_attribute_parse(
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list,
    _Out_ switch_direction_t *direction,
    _Out_ switch_qos_map_ingress_t *ingress_qos_map_type,
    _Out_ switch_qos_map_egress_t *egress_qos_map_type,
    _Out_ uint32_t *num_entries,
    _Out_ switch_qos_map_t **switch_qos_map_list) {
  const sai_attribute_t *attribute;
  uint32_t i = 0, j = 0;
  sai_status_t status = SAI_STATUS_SUCCESS;
  sai_qos_map_t *qos_map = NULL;
  switch_qos_map_t *switch_qos_map = NULL;
  sai_qos_map_type_t qos_map_type = 0;

  for (i = 0; i < attr_count; i++) {
    attribute = &attr_list[i];
    switch (attribute->id) {
      case SAI_QOS_MAP_ATTR_TYPE:
        status = sai_qos_map_type_to_switch_qos_map_type(attribute->value.u32,
                                                         direction,
                                                         ingress_qos_map_type,
                                                         egress_qos_map_type);
        if (status != SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("qos map attribute parse failed %s",
                        sai_status_to_string(status));
          return status;
        }
        qos_map_type = attribute->value.u32;
        break;
      case SAI_QOS_MAP_ATTR_MAP_TO_VALUE_LIST:
        *num_entries = attribute->value.qosmap.count;
        *switch_qos_map_list =
            SAI_MALLOC(sizeof(switch_qos_map_t) * (*num_entries));
        if (!(*switch_qos_map_list)) {
          status = SAI_STATUS_NO_MEMORY;
          SAI_LOG_ERROR("memory allocation failed for qos map %s",
                        sai_status_to_string(status));
          return status;
        }

        memset(*switch_qos_map_list,
               0x0,
               sizeof(switch_qos_map_t) * (*num_entries));
        for (j = 0; j < (*num_entries); j++) {
          qos_map = &attribute->value.qosmap.list[j];
          switch_qos_map = &(*switch_qos_map_list)[j];
          sai_qos_map_to_switch_qos_map(qos_map_type, qos_map, switch_qos_map);
        }
        break;
      default:
        break;
    }
  }

  return status;
}

/**
 * @brief Create Qos Map
 *
 * @param[out] qos_map_id Qos Map Id
 * @param[in] attr_count number of attributes
 * @param[in] attr_list array of attributes
 *
 * @return  SAI_STATUS_SUCCESS on success
 *          Failure status code on error
 */
sai_status_t sai_create_qos_map(_Out_ sai_object_id_t *qos_map_id,
                                _In_ uint32_t attr_count,
                                _In_ const sai_attribute_t *attr_list) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;
  uint32_t num_entries = 0;
  switch_qos_map_t *switch_qos_map_list = NULL;
  switch_direction_t direction = 0;
  switch_qos_map_ingress_t ingress_qos_map_type = 0;
  switch_qos_map_egress_t egress_qos_map_type = 0;

  status = sai_qos_map_attribute_parse(attr_count,
                                       attr_list,
                                       &direction,
                                       &ingress_qos_map_type,
                                       &egress_qos_map_type,
                                       &num_entries,
                                       &switch_qos_map_list);
  if (status != SAI_STATUS_SUCCESS) {
    SAI_LOG_ERROR("qos map attribute parse failed %s",
                  sai_status_to_string(status));
    return status;
  }

  if (direction == SWITCH_API_DIRECTION_INGRESS) {
    *qos_map_id = switch_api_qos_map_ingress_create(
        device, ingress_qos_map_type, num_entries, switch_qos_map_list);
  } else {
    *qos_map_id = switch_api_qos_map_egress_create(
        device, egress_qos_map_type, num_entries, switch_qos_map_list);
  }

  status = (*qos_map_id == SWITCH_API_INVALID_HANDLE) ? SAI_STATUS_FAILURE
                                                      : SAI_STATUS_SUCCESS;

  if (status != SAI_STATUS_SUCCESS) {
    SAI_LOG_ERROR("failed to create qos map group: %s",
                  sai_status_to_string(status));
  }

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/**
 * @brief Remove Qos Map
 *
 *  @param[in] qos_map_id Qos Map id to be removed.
 *
 *  @return  SAI_STATUS_SUCCESS on success
 *           Failure status code on error
 */
sai_status_t sai_remove_qos_map(_In_ sai_object_id_t qos_map_id) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(qos_map_id) == SAI_OBJECT_TYPE_QOS_MAP);

  status = switch_api_qos_map_ingress_delete(device, qos_map_id);
  if (status != SWITCH_STATUS_SUCCESS &&
      status != SWITCH_STATUS_INVALID_HANDLE) {
    SAI_LOG_ERROR("failed to remove ingress qos map %s",
                  sai_status_to_string(status));
    return status;
  }

  status = switch_api_qos_map_egress_delete(device, qos_map_id);
  if (status != SWITCH_STATUS_SUCCESS) {
    SAI_LOG_ERROR("failed to remove egress qos map %s",
                  sai_status_to_string(status));
    return status;
  }

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/**
 * @brief Set attributes for qos map
 *
 * @param[in] qos_map_id Qos Map Id
 * @param[in] attr attribute to set
 *
 * @return  SAI_STATUS_SUCCESS on success
 *          Failure status code on error
 */

sai_status_t sai_set_qos_map_attribute(_In_ sai_object_id_t qos_map_id,
                                       _In_ const sai_attribute_t *attr) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(qos_map_id) == SAI_OBJECT_TYPE_QOS_MAP);

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/**
 * @brief  Get attrbutes of qos map
 *
 * @param[in] qos_map_id  map id
 * @param[in] attr_count  number of attributes
 * @param[inout] attr_list  array of attributes
 *
 * @return SAI_STATUS_SUCCESS on success
 *        Failure status code on error
 */

sai_status_t sai_get_qos_map_attribute(_In_ sai_object_id_t qos_map_id,
                                       _In_ uint32_t attr_count,
                                       _Inout_ sai_attribute_t *attr_list) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_ASSERT(sai_object_type_query(qos_map_id) == SAI_OBJECT_TYPE_QOS_MAP);

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/*
*  Qos maps methods table retrieved with sai_api_query()
*/
sai_qos_map_api_t qos_api = {
    .create_qos_map = sai_create_qos_map,
    .remove_qos_map = sai_remove_qos_map,
    .set_qos_map_attribute = sai_set_qos_map_attribute,
    .get_qos_map_attribute = sai_get_qos_map_attribute};

sai_status_t sai_qos_map_initialize(sai_api_service_t *sai_api_service) {
  SAI_LOG_DEBUG("Initializing qos map");
  sai_api_service->qos_api = qos_api;
  return SAI_STATUS_SUCCESS;
}
