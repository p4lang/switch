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

#include <saiport.h>
#include "saiinternal.h"
#include <switchapi/switch_port.h>
#include <switchapi/switch_capability.h>

static sai_api_t api_id = SAI_API_PORT;

/*
* Routine Description:
*   Set port attribute value.
*
* Arguments:
*    [in] port_id - port id
*    [in] attr - attribute
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_set_port_attribute(_In_ sai_object_id_t port_id,
                                    _In_ const sai_attribute_t *attr) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
  switch_handle_t vlan_handle = SWITCH_API_INVALID_HANDLE;
  switch_port_speed_t port_speed;
  bool trust = FALSE;

  if (!attr) {
    status = SAI_STATUS_INVALID_PARAMETER;
    SAI_LOG_ERROR("null attribute: %s", sai_status_to_string(status));
    return status;
  }

  switch (attr->id) {
    case SAI_PORT_ATTR_PORT_VLAN_ID:
      switch_status = switch_api_vlan_id_to_handle_get(
          (switch_vlan_t)attr->value.u16, &vlan_handle);
      status = sai_switch_status_to_sai_status(switch_status);
      if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to get vlan %d: %s",
                      sai_status_to_string(status));
        return status;
      }
      /* TBD: Default BD */
      break;

    case SAI_PORT_ATTR_QOS_DEFAULT_TC:
      switch_status =
          switch_api_port_tc_default_set(device, port_id, attr->value.u8);
      status = sai_switch_status_to_sai_status(switch_status);
      if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to set default tc for port %d: %s",
                      sai_status_to_string(status));
        return status;
      }
      break;
    case SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL:
      // need for disabling ports on shutdown
      break;
    case SAI_PORT_ATTR_INGRESS_FILTERING:
      // need to enable ingress filtering
      break;
    case SAI_PORT_ATTR_SPEED:
      if ((status = sai_port_speed_to_switch_port_speed(
               attr->value.u32, &port_speed)) != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("bad port speed for port %d speed: %s",
                      (port_id & 0xFFFF),
                      sai_status_to_string(status));
        return status;
      }
      switch_status =
          switch_api_port_speed_set(device,
                                    (switch_port_t)(port_id & 0xFFFF),
                                    (switch_port_speed_t)attr->value.u8);
      if ((status = sai_switch_status_to_sai_status(switch_status)) !=
          SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to set port %d speed: %s",
                      (port_id & 0xFFFF),
                      sai_status_to_string(status));
        return status;
      }
    case SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP:
    case SAI_PORT_ATTR_QOS_DSCP_TO_COLOR_MAP:
      trust = attr->value.oid != 0 ? TRUE : FALSE;
      switch_status = switch_api_port_trust_dscp_set(device, port_id, trust);
      status = sai_switch_status_to_sai_status(switch_status);
      if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to set dscp trust for port %d: %s",
                      sai_status_to_string(status));
        return status;
      }
      switch_status = switch_api_port_qos_group_ingress_set(
          device, port_id, attr->value.oid);
      status = sai_switch_status_to_sai_status(switch_status);
      if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to set ingress qos handle for port %d: %s",
                      sai_status_to_string(status));
        return status;
      }

      break;

    case SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP:
    case SAI_PORT_ATTR_QOS_TC_TO_PRIORITY_GROUP_MAP:
      switch_status =
          switch_api_port_qos_group_tc_set(device, port_id, attr->value.oid);
      status = sai_switch_status_to_sai_status(switch_status);
      if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to set ingress tc handle for port %d: %s",
                      sai_status_to_string(status));
        return status;
      }
      break;

    case SAI_PORT_ATTR_QOS_TC_AND_COLOR_TO_DOT1P_MAP:
    case SAI_PORT_ATTR_QOS_TC_AND_COLOR_TO_DSCP_MAP:
      switch_status = switch_api_port_qos_group_egress_set(
          device, port_id, attr->value.oid);
      status = sai_switch_status_to_sai_status(switch_status);
      if (status != SAI_STATUS_SUCCESS) {
        SAI_LOG_ERROR("failed to set egress qos handle for port %d: %s",
                      sai_status_to_string(status));
        return status;
      }
      break;

    default:
      break;
  }

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/*
* Routine Description:
*   Get port attribute value.
*
* Arguments:
*    [in] port_id - port id
*    [in] attr_count - number of attributes
*    [inout] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_get_port_attribute(_In_ sai_object_id_t port_id,
                                    _In_ uint32_t attr_count,
                                    _Inout_ sai_attribute_t *attr_list) {
  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
  unsigned int i = 0;
  sai_attribute_t *attr = attr_list;
  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_LOG_ENTER();

  if (!attr_list) {
    status = SAI_STATUS_INVALID_PARAMETER;
    SAI_LOG_ERROR("null attribute list: %s", sai_status_to_string(status));
    return status;
  }

  for (i = 0, attr = attr_list; i < attr_count; i++, attr++) {
    switch (attr->id) {
      case SAI_PORT_ATTR_TYPE: {
        switch_api_capability_t api_switch_info;
        switch_api_capability_get(device, &api_switch_info);
        if (api_switch_info.port_list[64] == port_id)
          attr->value.s32 = SAI_PORT_TYPE_CPU;
        else
          attr->value.s32 = SAI_PORT_TYPE_LOGICAL;
        status = sai_switch_status_to_sai_status(switch_status);
      } break;

      case SAI_PORT_ATTR_HW_LANE_LIST:
        attr->value.u32list.count = 1;
        attr->value.u32list.list[0] = port_id & 0xFFFF;
        status = sai_switch_status_to_sai_status(switch_status);
        break;

      case SAI_PORT_ATTR_SUPPORTED_BREAKOUT_MODE:
        attr->value.s32list.count = 1;
        attr->value.s32list.list[0] = SAI_PORT_BREAKOUT_MODE_TYPE_1_LANE;
        status = sai_switch_status_to_sai_status(switch_status);
        break;

      case SAI_PORT_ATTR_CURRENT_BREAKOUT_MODE:
        attr->value.s32 = SAI_PORT_BREAKOUT_MODE_TYPE_1_LANE;
        status = sai_switch_status_to_sai_status(switch_status);
        break;
      case SAI_PORT_ATTR_OPER_STATUS:
        switch_status = switch_api_port_state_get(
            device, (switch_port_t)(port_id & 0xFFFF), &(attr->value.booldata));
        if ((status = sai_switch_status_to_sai_status(switch_status)) !=
            SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get port %d oper state: %s",
                        (port_id & 0xFFFF),
                        sai_status_to_string(status));
          return status;
        }
        status = sai_switch_port_enabled_to_sai_oper_status(attr);
        attr->value.s32 = SAI_PORT_OPER_STATUS_UP;
        status = sai_switch_status_to_sai_status(switch_status);
        break;
      case SAI_PORT_ATTR_SPEED:
        switch_status =
            switch_api_port_speed_get(device,
                                      (switch_port_t)(port_id & 0xFFFF),
                                      (switch_port_speed_t *)&attr->value.u8);
        if ((status = sai_switch_status_to_sai_status(switch_status)) !=
            SAI_STATUS_SUCCESS) {
          SAI_LOG_ERROR("failed to get port %d speed: %s",
                        (port_id & 0xFFFF),
                        sai_status_to_string(status));
          return status;
        }
        attr->value.u32 = 40000;  // SAI_PORT_SPEED_FORTY_GIG;
        break;
      case SAI_PORT_ATTR_SUPPORTED_SPEED:
        // TODO: implement this, should return list of supported port speeds
        attr->value.u32list.count = 0;
        break;
      case SAI_PORT_ATTR_QOS_NUMBER_OF_SCHEDULER_GROUPS:
        attr->value.u32list.count = 0;
        break;
      default:
        status = SAI_STATUS_NOT_SUPPORTED;
        break;
    }
  }

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/*
* Routine Description:
*   Get port statistics counters.
*
* Arguments:
*    [in] port_id - port id
*    [in] counter_ids - specifies the array of counter ids
*    [in] number_of_counters - number of counters in the array
*    [out] counters - array of resulting counter values.
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/
sai_status_t sai_get_port_stats(_In_ sai_object_id_t port_id,
                                _In_ const sai_port_stat_t *counter_ids,
                                _In_ uint32_t number_of_counters,
                                _Out_ uint64_t *counters) {
  SAI_LOG_ENTER();

  sai_status_t status = SAI_STATUS_SUCCESS;

  SAI_LOG_EXIT();

  return (sai_status_t)status;
}

/*
* Port methods table retrieved with sai_api_query()
*/
sai_port_api_t port_api = {.set_port_attribute = sai_set_port_attribute,
                           .get_port_attribute = sai_get_port_attribute,
                           .get_port_stats = sai_get_port_stats};

sai_status_t sai_port_initialize(sai_api_service_t *sai_api_service) {
  SAI_LOG_DEBUG("Initializing port");
  sai_api_service->port_api = port_api;
  return SAI_STATUS_SUCCESS;
}
