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
#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_status.h"
#include "switchapi/switch_utils.h"
#include "switch_qos_int.h"
#include "switch_pd.h"
#include "switch_log_int.h"
#include "switch_defines.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static void *switch_qos_map_array;
switch_api_id_allocator *ingress_qos_map_id = NULL;
switch_api_id_allocator *tc_qos_map_id = NULL;
switch_api_id_allocator *egress_qos_map_id = NULL;

switch_status_t switch_qos_init(switch_device_t device) {
  switch_qos_map_array = NULL;
  switch_handle_type_init(SWITCH_HANDLE_TYPE_QOS_MAP, 128);
  ingress_qos_map_id = switch_api_id_allocator_new(32, FALSE);
  egress_qos_map_id = switch_api_id_allocator_new(32, FALSE);
  tc_qos_map_id = switch_api_id_allocator_new(32, FALSE);
  return SWITCH_STATUS_SUCCESS;
}

switch_handle_t switch_qos_map_handle_create() {
  switch_handle_t qos_map_handle;
  _switch_handle_create(SWITCH_HANDLE_TYPE_QOS_MAP,
                        switch_qos_map_list_t,
                        switch_qos_map_array,
                        NULL,
                        qos_map_handle);
  return qos_map_handle;
}

switch_qos_map_list_t *switch_qos_map_get(switch_handle_t qos_map_handle) {
  switch_qos_map_list_t *qos_map_list = NULL;
  _switch_handle_get(switch_qos_map_list_t,
                     switch_qos_map_array,
                     qos_map_handle,
                     qos_map_list);
  return qos_map_list;
}

switch_status_t switch_qos_map_handle_delete(switch_handle_t qos_map_handle) {
  _switch_handle_delete(
      switch_qos_map_list_t, switch_qos_map_array, qos_map_handle);
  return SWITCH_STATUS_SUCCESS;
}

switch_handle_t switch_api_qos_map_ingress_create(
    switch_device_t device,
    switch_qos_map_ingress_t qos_map_type,
    uint8_t num_entries,
    switch_qos_map_t *qos_map) {
  switch_qos_map_list_t *qos_map_list_info = NULL;
  switch_qos_map_info_t *qos_map_info = NULL;
  switch_handle_t qos_map_handle = 0;
  switch_qos_group_t qos_group = 0;
  int index = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  qos_map_handle = switch_qos_map_handle_create();
  qos_map_list_info = switch_qos_map_get(qos_map_handle);
  if (!qos_map_list_info) {
    SWITCH_API_ERROR("qos map create failed");
    return SWITCH_API_INVALID_HANDLE;
  }

  tommy_list_init(&qos_map_list_info->qos_map_list);
  switch (qos_map_type) {
    case SWITCH_QOS_MAP_INGRESS_DSCP_TO_TC:
    case SWITCH_QOS_MAP_INGRESS_PCP_TO_TC:
    case SWITCH_QOS_MAP_INGRESS_DSCP_TO_COLOR:
    case SWITCH_QOS_MAP_INGRESS_PCP_TO_COLOR:
    case SWITCH_QOS_MAP_INGRESS_DSCP_TO_TC_AND_COLOR:
    case SWITCH_QOS_MAP_INGRESS_PCP_TO_TC_AND_COLOR:
      qos_group = switch_api_id_allocator_allocate(ingress_qos_map_id);
      break;
    case SWITCH_QOS_MAP_INGRESS_TC_TO_ICOS:
    case SWITCH_QOS_MAP_INGRESS_TC_TO_QUEUE:
    case SWITCH_QOS_MAP_INGRESS_TC_TO_ICOS_AND_QUEUE:
      qos_group = switch_api_id_allocator_allocate(tc_qos_map_id);
      break;
    default:
      return SWITCH_API_INVALID_HANDLE;
  }

  for (index = 0; index < num_entries; index++) {
    qos_map_info = switch_malloc(sizeof(switch_qos_map_info_t), 1);
    if (!qos_map_info) {
      SWITCH_API_ERROR("qos map create failed. no memory");
      return SWITCH_API_INVALID_HANDLE;
    }

    status = switch_pd_qos_map_ingress_entry_add(device,
                                                 qos_map_type,
                                                 qos_group,
                                                 &qos_map[index],
                                                 &qos_map_info->pd_hdl);

    memcpy(&qos_map_info->qos_map, &qos_map[index], sizeof(switch_qos_map_t));

    tommy_list_insert_head(
        &qos_map_list_info->qos_map_list, &qos_map_info->node, qos_map_info);
  }

  qos_map_list_info->qos_group = qos_group;
  qos_map_list_info->map_type.ingress_map_type = qos_map_type;
  qos_map_list_info->direction = SWITCH_API_DIRECTION_INGRESS;

  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("qos map create failed");
    return SWITCH_API_INVALID_HANDLE;
  }

  return qos_map_handle;
}

switch_status_t switch_api_qos_map_ingress_delete(
    switch_device_t device, switch_handle_t qos_map_handle) {
  switch_qos_map_list_t *qos_map_list_info = NULL;
  switch_qos_map_info_t *qos_map_info = NULL;
  tommy_node *node = NULL;
  tommy_node *next_node = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  qos_map_list_info = switch_qos_map_get(qos_map_handle);
  if (!qos_map_list_info) {
    SWITCH_API_ERROR("qos map delete failed");
    return SWITCH_STATUS_INVALID_PARAMETER;
  }

  node = tommy_list_head(&qos_map_list_info->qos_map_list);
  while (node) {
    qos_map_info = node->data;
    status = switch_pd_qos_map_ingress_entry_delete(
        device,
        qos_map_list_info->map_type.ingress_map_type,
        qos_map_info->pd_hdl);
    if (status != SWITCH_STATUS_SUCCESS) {
      SWITCH_API_ERROR("qos map deleted failed: ingress");
    }
    next_node = node->next;
    tommy_list_remove_existing(&qos_map_list_info->qos_map_list, node);
    switch_free(qos_map_info);
    node = next_node;
  }

  switch (qos_map_list_info->map_type.ingress_map_type) {
    case SWITCH_QOS_MAP_INGRESS_DSCP_TO_TC:
    case SWITCH_QOS_MAP_INGRESS_PCP_TO_TC:
    case SWITCH_QOS_MAP_INGRESS_DSCP_TO_COLOR:
    case SWITCH_QOS_MAP_INGRESS_PCP_TO_COLOR:
    case SWITCH_QOS_MAP_INGRESS_DSCP_TO_TC_AND_COLOR:
    case SWITCH_QOS_MAP_INGRESS_PCP_TO_TC_AND_COLOR:
      switch_api_id_allocator_release(ingress_qos_map_id,
                                      qos_map_list_info->qos_group);
      break;
    case SWITCH_QOS_MAP_INGRESS_TC_TO_ICOS:
    case SWITCH_QOS_MAP_INGRESS_TC_TO_QUEUE:
    case SWITCH_QOS_MAP_INGRESS_TC_TO_ICOS_AND_QUEUE:
      switch_api_id_allocator_release(tc_qos_map_id,
                                      qos_map_list_info->qos_group);
      break;
    default:
      break;
  }

  status = switch_qos_map_handle_delete(qos_map_handle);
  return status;
}

switch_handle_t switch_api_qos_map_egress_create(
    switch_device_t device,
    switch_qos_map_egress_t qos_map_type,
    uint8_t num_entries,
    switch_qos_map_t *qos_map) {
  switch_qos_map_list_t *qos_map_list_info = NULL;
  switch_qos_map_info_t *qos_map_info = NULL;
  switch_handle_t qos_map_handle = 0;
  switch_qos_group_t qos_group = 0;
  int index = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  qos_map_handle = switch_qos_map_handle_create();
  qos_map_list_info = switch_qos_map_get(qos_map_handle);
  if (!qos_map_list_info) {
    SWITCH_API_ERROR("qos map create failed");
    return SWITCH_API_INVALID_HANDLE;
  }

  tommy_list_init(&qos_map_list_info->qos_map_list);
  qos_group = switch_api_id_allocator_allocate(egress_qos_map_id);

  for (index = 0; index < num_entries; index++) {
    qos_map_info = switch_malloc(sizeof(switch_qos_map_info_t), 1);
    if (!qos_map_info) {
      SWITCH_API_ERROR("qos map create failed. no memory");
      return SWITCH_API_INVALID_HANDLE;
    }

    status = switch_pd_qos_map_egress_entry_add(device,
                                                qos_map_type,
                                                qos_group,
                                                &qos_map[index],
                                                &qos_map_info->pd_hdl);

    memcpy(&qos_map_info->qos_map, &qos_map[index], sizeof(switch_qos_map_t));

    tommy_list_insert_head(
        &qos_map_list_info->qos_map_list, &qos_map_info->node, qos_map_info);
  }

  qos_map_list_info->qos_group = qos_group;
  qos_map_list_info->direction = SWITCH_API_DIRECTION_EGRESS;
  qos_map_list_info->map_type.egress_map_type = qos_map_type;

  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("qos map create failed");
    return SWITCH_API_INVALID_HANDLE;
  }

  return qos_map_handle;
}

switch_status_t switch_api_qos_map_egress_delete(
    switch_device_t device, switch_handle_t qos_map_handle) {
  switch_qos_map_list_t *qos_map_list_info = NULL;
  switch_qos_map_info_t *qos_map_info = NULL;
  tommy_node *node = NULL;
  tommy_node *next_node = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  qos_map_list_info = switch_qos_map_get(qos_map_handle);
  if (!qos_map_list_info) {
    SWITCH_API_ERROR("qos map delete failed");
    return SWITCH_STATUS_INVALID_PARAMETER;
  }

  node = tommy_list_head(&qos_map_list_info->qos_map_list);
  while (node) {
    qos_map_info = node->data;
    status = switch_pd_qos_map_egress_entry_delete(
        device,
        qos_map_list_info->map_type.egress_map_type,
        qos_map_info->pd_hdl);
    if (status != SWITCH_STATUS_SUCCESS) {
      SWITCH_API_ERROR("qos map deleted failed: egress");
    }
    next_node = node->next;
    tommy_list_remove_existing(&qos_map_list_info->qos_map_list, node);
    switch_free(qos_map_info);
    node = next_node;
  }

  switch_api_id_allocator_release(egress_qos_map_id,
                                  qos_map_list_info->qos_group);

  status = switch_qos_map_handle_delete(qos_map_handle);
  return status;
}

#ifdef __cplusplus
}
#endif
