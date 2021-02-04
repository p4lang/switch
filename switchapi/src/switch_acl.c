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
#include "p4features.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_status.h"
#include "switchapi/switch_acl.h"
#include "switch_acl_int.h"
#include "switch_interface_int.h"
#include "switch_pd.h"
#include "switch_log_int.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static void *switch_acl_array;
static void *switch_range_array;
switch_api_id_allocator *acl_counter_index = NULL;

switch_status_t switch_acl_init(switch_device_t device) {
  switch_acl_array = NULL;
  switch_handle_type_init(SWITCH_HANDLE_TYPE_ACL, (4 * 1024));
  switch_handle_type_init(SWITCH_HANDLE_TYPE_ACE, (4 * 1024));
  switch_handle_type_init(SWITCH_HANDLE_TYPE_RANGE, (1024));
  acl_counter_index = switch_api_id_allocator_new(4 * 1024, FALSE);
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_acl_free(switch_device_t device) {
  switch_api_id_allocator_destroy(acl_counter_index);
  switch_handle_type_free(SWITCH_HANDLE_TYPE_ACE);
  switch_handle_type_free(SWITCH_HANDLE_TYPE_ACL);
  switch_handle_type_free(SWITCH_HANDLE_TYPE_RANGE);
  return SWITCH_STATUS_SUCCESS;
}

switch_handle_t switch_acl_create() {
  switch_handle_t acl_handle;
  _switch_handle_create(SWITCH_HANDLE_TYPE_ACL,
                        switch_acl_info_t,
                        switch_acl_array,
                        NULL,
                        acl_handle);
  return acl_handle;
}

switch_acl_info_t *switch_acl_get(switch_handle_t acl_handle) {
  switch_acl_info_t *acl_info = NULL;
  _switch_handle_get(switch_acl_info_t, switch_acl_array, acl_handle, acl_info);
  return acl_info;
}

switch_status_t switch_acl_delete(switch_handle_t handle) {
  _switch_handle_delete(switch_acl_info_t, switch_acl_array, handle);
  return SWITCH_STATUS_SUCCESS;
}

unsigned int switch_acl_counter_index_allocate() {
  return switch_api_id_allocator_allocate(acl_counter_index);
}

void switch_acl_counter_index_free(unsigned int index) {
  switch_api_id_allocator_release(acl_counter_index, index);
}

switch_handle_t switch_api_acl_list_create(switch_device_t device,
                                           switch_direction_t direction,
                                           switch_acl_type_t type) {
  switch_acl_info_t *acl_info = NULL;
  switch_handle_t acl_handle;

  acl_handle = switch_acl_create();
  acl_info = switch_acl_get(acl_handle);
  if (!acl_info) {
    return SWITCH_STATUS_NO_MEMORY;
  }
  acl_info->type = type;
  acl_info->direction = direction;
  acl_info->rules = NULL;
  tommy_list_init(&(acl_info->interface_list));
  return acl_handle;
}

switch_handle_t switch_api_acl_list_update(switch_device_t device,
                                           switch_handle_t acl_handle,
                                           switch_acl_type_t type) {
  switch_acl_info_t *acl_info = NULL;

  acl_info = switch_acl_get(acl_handle);
  if (!acl_info) {
    return SWITCH_STATUS_INVALID_HANDLE;
  }
  acl_info->type = type;
  return acl_handle;
}

switch_status_t switch_api_acl_list_delete(switch_device_t device,
                                           switch_handle_t acl_handle) {
  switch_acl_info_t *acl_info = NULL;

  acl_info = switch_acl_get(acl_handle);
  if (!acl_info) {
    return SWITCH_STATUS_INVALID_HANDLE;
  }
  switch_acl_delete(acl_handle);
  return SWITCH_STATUS_SUCCESS;
}

// redundant typedef below! TBD remove it
typedef switch_acl_rule_t switch_ace_info_t;

static void *switch_ace_array;

static switch_handle_t switch_ace_create() {
  switch_handle_t ace_handle;
  _switch_handle_create(SWITCH_HANDLE_TYPE_ACE,
                        switch_ace_info_t,
                        switch_ace_array,
                        NULL,
                        ace_handle);
  return ace_handle;
}

static switch_ace_info_t *switch_ace_get(switch_handle_t ace_handle) {
  switch_ace_info_t *ace_info = NULL;
  _switch_handle_get(switch_ace_info_t, switch_ace_array, ace_handle, ace_info);
  return ace_info;
}

static switch_status_t switch_ace_delete(switch_handle_t handle) {
  _switch_handle_delete(switch_ace_info_t, switch_ace_array, handle);
  return SWITCH_STATUS_SUCCESS;
}

static switch_status_t switch_acl_ip_set_fields_actions(
    switch_device_t device,
    switch_direction_t direction,
    switch_acl_rule_t *p,
    switch_handle_t interface_handle,
    p4_pd_entry_hdl_t *entry) {
  switch_acl_ip_key_value_pair_t *ip_acl = NULL;
  switch_interface_info_t *intf_info = NULL;
  uint16_t bd_label = 0;
  uint16_t if_label = 0;
  uint8_t nat_mode = SWITCH_NAT_MODE_NONE;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (interface_handle) {
    if (switch_handle_get_type(interface_handle) == SWITCH_HANDLE_TYPE_PORT) {
      if_label = handle_to_id(interface_handle) + 1;
    } else {
      intf_info = switch_api_interface_get(interface_handle);
      if (!intf_info) {
        return SWITCH_STATUS_INVALID_INTERFACE;
      }
      switch (switch_handle_get_type(interface_handle)) {
        case SWITCH_HANDLE_TYPE_INTERFACE:
          if_label =
              handle_to_id(intf_info->api_intf_info.u.port_lag_handle) + 1;
          break;
        case SWITCH_HANDLE_TYPE_BD:
          bd_label = handle_to_id(interface_handle) + 1;
          ;
          break;
        default:
          return SWITCH_STATUS_INVALID_HANDLE;
      }
      status = switch_api_interface_nat_mode_get(interface_handle, &nat_mode);
      if (status == SWITCH_STATUS_SUCCESS) {
        p->opt_action_params.nat_mode = nat_mode;
      }
    }
  }
  ip_acl = (switch_acl_ip_key_value_pair_t *)p->fields;

  if (direction == SWITCH_API_DIRECTION_INGRESS) {
    status = switch_pd_ipv4_acl_table_add_entry(device,
                                                if_label,
                                                bd_label,
                                                p->priority,
                                                p->field_count,
                                                ip_acl,
                                                p->action,
                                                &(p->action_params),
                                                &(p->opt_action_params),
                                                entry);
  } else {
    status = switch_pd_egress_ipv4_acl_table_add_entry(device,
                                                       if_label,
                                                       bd_label,
                                                       p->priority,
                                                       p->field_count,
                                                       ip_acl,
                                                       p->action,
                                                       &(p->action_params),
                                                       &(p->opt_action_params),
                                                       entry);
  }
  return status;
}

static switch_status_t switch_acl_ipv6_set_fields_actions(
    switch_device_t device,
    switch_direction_t direction,
    switch_acl_rule_t *p,
    switch_handle_t interface_handle,
    p4_pd_entry_hdl_t *entry) {
  switch_acl_ipv6_key_value_pair_t *ipv6_acl = NULL;
  switch_interface_info_t *intf_info = NULL;
  uint16_t bd_label = 0;
  uint16_t if_label = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (interface_handle) {
    if (switch_handle_get_type(interface_handle) == SWITCH_HANDLE_TYPE_PORT) {
      if_label = handle_to_id(interface_handle) + 1;
    } else {
      intf_info = switch_api_interface_get(interface_handle);
      if (!intf_info) {
        return SWITCH_STATUS_INVALID_INTERFACE;
      }
      switch (switch_handle_get_type(interface_handle)) {
        case SWITCH_HANDLE_TYPE_INTERFACE:
          if_label =
              handle_to_id(intf_info->api_intf_info.u.port_lag_handle) + 1;
          break;
        case SWITCH_HANDLE_TYPE_BD:
          bd_label = handle_to_id(interface_handle) + 1;
          ;
          break;
        default:
          return SWITCH_STATUS_INVALID_HANDLE;
      }
    }
  }
  ipv6_acl = (switch_acl_ipv6_key_value_pair_t *)p->fields;

  if (direction == SWITCH_API_DIRECTION_INGRESS) {
    status = switch_pd_ipv6_acl_table_add_entry(device,
                                                if_label,
                                                bd_label,
                                                p->priority,
                                                p->field_count,
                                                ipv6_acl,
                                                p->action,
                                                &(p->action_params),
                                                &(p->opt_action_params),
                                                entry);
  } else {
    status = switch_pd_egress_ipv6_acl_table_add_entry(device,
                                                       if_label,
                                                       bd_label,
                                                       p->priority,
                                                       p->field_count,
                                                       ipv6_acl,
                                                       p->action,
                                                       &(p->action_params),
                                                       &(p->opt_action_params),
                                                       entry);
  }
  return status;
}

static switch_status_t switch_acl_mac_set_fields_actions(
    switch_device_t device,
    switch_direction_t direction,
    switch_acl_rule_t *p,
    switch_handle_t interface_handle,
    p4_pd_entry_hdl_t *entry) {
  switch_acl_mac_key_value_pair_t *mac_acl = NULL;
  switch_interface_info_t *intf_info = NULL;
  uint16_t bd_label = 0;
  uint16_t if_label = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (interface_handle) {
    intf_info = switch_api_interface_get(interface_handle);
    if (!intf_info) {
      return SWITCH_STATUS_INVALID_INTERFACE;
    }
    switch (switch_handle_get_type(interface_handle)) {
      case SWITCH_HANDLE_TYPE_INTERFACE:
        if_label = handle_to_id(intf_info->api_intf_info.u.port_lag_handle) + 1;
        break;
      case SWITCH_HANDLE_TYPE_BD:
        bd_label = handle_to_id(interface_handle) + 1;
        ;
        break;
      default:
        return SWITCH_STATUS_INVALID_HANDLE;
    }
  }

  mac_acl = (switch_acl_mac_key_value_pair_t *)p->fields;
  if (direction == SWITCH_API_DIRECTION_INGRESS) {
    status = switch_pd_mac_acl_table_add_entry(device,
                                               if_label,
                                               bd_label,
                                               p->priority,
                                               p->field_count,
                                               mac_acl,
                                               p->action,
                                               &(p->action_params),
                                               &(p->opt_action_params),
                                               entry);
  } else {
    status = switch_pd_egress_mac_acl_table_add_entry(device,
                                                      if_label,
                                                      bd_label,
                                                      p->priority,
                                                      p->field_count,
                                                      mac_acl,
                                                      p->action,
                                                      &(p->action_params),
                                                      &(p->opt_action_params),
                                                      entry);
  }

  return status;
}

static switch_status_t switch_acl_ip_racl_set_fields_actions(
    switch_device_t device,
    switch_direction_t direction,
    switch_acl_rule_t *p,
    switch_handle_t interface_handle,
    p4_pd_entry_hdl_t *entry) {
  switch_acl_ip_racl_key_value_pair_t *ip_racl = NULL;
  uint16_t bd_label = 0;
  uint16_t if_label = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (interface_handle) {
    switch (switch_handle_get_type(interface_handle)) {
      case SWITCH_HANDLE_TYPE_BD:
        bd_label = handle_to_id(interface_handle) + 1;
        ;
        break;
      default:
        return SWITCH_STATUS_INVALID_HANDLE;
    }
  }
  ip_racl = (switch_acl_ip_racl_key_value_pair_t *)p->fields;

  if (direction == SWITCH_API_DIRECTION_INGRESS) {
    status = switch_pd_ipv4_racl_table_add_entry(device,
                                                 if_label,
                                                 bd_label,
                                                 p->priority,
                                                 p->field_count,
                                                 ip_racl,
                                                 p->action,
                                                 &(p->action_params),
                                                 &(p->opt_action_params),
                                                 entry);
  } else {
    status = SWITCH_STATUS_NOT_SUPPORTED;
  }
  return status;
}

static switch_status_t switch_acl_ipv6_racl_set_fields_actions(
    switch_device_t device,
    switch_direction_t direction,
    switch_acl_rule_t *p,
    switch_handle_t interface_handle,
    p4_pd_entry_hdl_t *entry) {
  switch_acl_ipv6_racl_key_value_pair_t *ipv6_racl = NULL;
  uint16_t bd_label = 0;
  uint16_t if_label = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (interface_handle) {
    switch (switch_handle_get_type(interface_handle)) {
      case SWITCH_HANDLE_TYPE_BD:
        bd_label = handle_to_id(interface_handle) + 1;
        ;
        break;
      default:
        return SWITCH_STATUS_INVALID_HANDLE;
        break;
    }
  }
  ipv6_racl = (switch_acl_ipv6_racl_key_value_pair_t *)p->fields;

  if (direction == SWITCH_API_DIRECTION_INGRESS) {
    status = switch_pd_ipv6_racl_table_add_entry(device,
                                                 if_label,
                                                 bd_label,
                                                 p->priority,
                                                 p->field_count,
                                                 ipv6_racl,
                                                 p->action,
                                                 &(p->action_params),
                                                 &(p->opt_action_params),
                                                 entry);
  } else {
    status = SWITCH_STATUS_NOT_SUPPORTED;
  }

  return status;
}

static switch_status_t switch_acl_system_set_fields_actions(
    switch_device_t device,
    switch_direction_t direction,
    switch_acl_rule_t *p,
    switch_handle_t interface_handle,
    p4_pd_entry_hdl_t *entry) {
  switch_acl_system_key_value_pair_t *system_acl = NULL;
  switch_interface_info_t *intf_info = NULL;
  uint16_t bd_label = 0;
  uint16_t if_label = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (interface_handle) {
    intf_info = switch_api_interface_get(interface_handle);
    if (!intf_info) {
      return SWITCH_STATUS_INVALID_INTERFACE;
    }
    switch (switch_handle_get_type(interface_handle)) {
      case SWITCH_HANDLE_TYPE_INTERFACE:
        if_label = handle_to_id(intf_info->api_intf_info.u.port_lag_handle) + 1;
        break;
      case SWITCH_HANDLE_TYPE_BD:
        bd_label = handle_to_id(interface_handle) + 1;
        ;
        break;
      default:
        return SWITCH_STATUS_INVALID_HANDLE;
    }
  }
  system_acl = (switch_acl_system_key_value_pair_t *)p->fields;
  if (direction == SWITCH_API_DIRECTION_INGRESS) {
    status = switch_pd_system_acl_table_add_entry(device,
                                                  if_label,
                                                  bd_label,
                                                  p->priority,
                                                  p->field_count,
                                                  system_acl,
                                                  p->action,
                                                  &p->action_params,
                                                  &p->opt_action_params,
                                                  entry);
  } else {
  }
  return status;
}

static switch_status_t switch_acl_egr_set_fields_actions(
    switch_device_t device,
    switch_direction_t direction,
    switch_acl_rule_t *p,
    switch_handle_t interface_handle,
    p4_pd_entry_hdl_t *entry) {
  switch_acl_egr_key_value_pair_t *egr_acl = NULL;
  switch_interface_info_t *intf_info = NULL;
  uint16_t bd_label = 0;
  uint16_t if_label = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (interface_handle) {
    if (switch_handle_get_type(interface_handle) == SWITCH_HANDLE_TYPE_PORT) {
      if_label = handle_to_id(interface_handle) + 1;
    } else {
      intf_info = switch_api_interface_get(interface_handle);
      if (!intf_info) {
        return SWITCH_STATUS_INVALID_INTERFACE;
      }
      switch (switch_handle_get_type(interface_handle)) {
        case SWITCH_HANDLE_TYPE_INTERFACE:
          if_label =
              handle_to_id(intf_info->api_intf_info.u.port_lag_handle) + 1;
          break;
        case SWITCH_HANDLE_TYPE_BD:
          bd_label = handle_to_id(interface_handle) + 1;
          ;
          break;
        default:
          return SWITCH_STATUS_INVALID_HANDLE;
      }
    }
  }
  egr_acl = (switch_acl_egr_key_value_pair_t *)p->fields;

  if (direction == SWITCH_API_DIRECTION_INGRESS) {
  } else {
    status = switch_pd_egr_acl_table_add_entry(device,
                                               if_label,
                                               bd_label,
                                               p->priority,
                                               p->field_count,
                                               egr_acl,
                                               p->action,
                                               &p->action_params,
                                               &p->opt_action_params,
                                               entry);
  }
  return status;
}

static switch_status_t acl_hw_set(switch_device_t device,
                                  switch_acl_info_t *acl_info,
                                  switch_acl_rule_t *p,
                                  switch_acl_interface_t *intf,
                                  switch_handle_t interface_handle,
                                  switch_handle_t ace_handle) {
  p4_pd_entry_hdl_t entry;
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  unsigned long *hw_entry = NULL;

  switch (acl_info->type) {
    case SWITCH_ACL_TYPE_SYSTEM:
      status = switch_acl_system_set_fields_actions(
          device, acl_info->direction, p, interface_handle, &entry);
      break;
    case SWITCH_ACL_TYPE_IP:
      status = switch_acl_ip_set_fields_actions(
          device, acl_info->direction, p, interface_handle, &entry);
      break;
    case SWITCH_ACL_TYPE_IPV6:
      status = switch_acl_ipv6_set_fields_actions(
          device, acl_info->direction, p, interface_handle, &entry);
      break;
    case SWITCH_ACL_TYPE_IP_RACL:
      status = switch_acl_ip_racl_set_fields_actions(
          device, acl_info->direction, p, interface_handle, &entry);
      break;
    case SWITCH_ACL_TYPE_IPV6_RACL:
      status = switch_acl_ipv6_racl_set_fields_actions(
          device, acl_info->direction, p, interface_handle, &entry);
      break;
    case SWITCH_ACL_TYPE_MAC:
      status = switch_acl_mac_set_fields_actions(
          device, acl_info->direction, p, interface_handle, &entry);
      break;
    case SWITCH_ACL_TYPE_EGRESS_SYSTEM:
      status = switch_acl_egr_set_fields_actions(
          device, acl_info->direction, p, interface_handle, &entry);
      break;
    default:
      break;
  }

  if (intf) {
    // use the ace_handle from rule list in the interface entries
    JLI(hw_entry, intf->entries, ace_handle);
    *(unsigned long *)hw_entry = entry;
  } else {
    // if there is no interface, store hw handle with ace data
    switch_acl_rule_t *rule = NULL;
    rule = switch_ace_get(ace_handle);
    rule->hw_entry = entry;
  }
  return status;
}

static switch_status_t acl_hw_del(switch_device_t device,
                                  switch_acl_info_t *acl_info,
                                  switch_acl_interface_t *intf,
                                  switch_handle_t ace_handle) {
  unsigned long *hw_entry = NULL;
  int ret = 0;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (!intf) {
    // in case there is no interface, hw handle is stored with ace
    if (acl_info->type != SWITCH_ACL_TYPE_SYSTEM)
      return SWITCH_STATUS_UNSUPPORTED_TYPE;

    return switch_pd_system_acl_table_delete_entry(
        device, acl_info->direction, switch_ace_get(ace_handle)->hw_entry);
  }

  JLG(hw_entry, intf->entries, ace_handle);
  if (hw_entry) {
    switch (acl_info->type) {
      case SWITCH_ACL_TYPE_SYSTEM:
        status = switch_pd_system_acl_table_delete_entry(
            device, acl_info->direction, *(unsigned long *)hw_entry);
        break;
      case SWITCH_ACL_TYPE_IP:
        status = switch_pd_ipv4_acl_table_delete_entry(
            device, acl_info->direction, *(unsigned long *)hw_entry);
        break;
      case SWITCH_ACL_TYPE_IPV6:
        status = switch_pd_ipv6_acl_table_delete_entry(
            device, acl_info->direction, *(unsigned long *)hw_entry);
        break;
      case SWITCH_ACL_TYPE_IP_RACL:
        status = switch_pd_ipv4_racl_table_delete_entry(
            device, acl_info->direction, *(unsigned long *)hw_entry);
        break;
      case SWITCH_ACL_TYPE_IPV6_RACL:
        status = switch_pd_ipv6_racl_table_delete_entry(
            device, acl_info->direction, *(unsigned long *)hw_entry);
        break;
      case SWITCH_ACL_TYPE_MAC:
        status = switch_pd_mac_acl_table_delete_entry(
            device, acl_info->direction, *(unsigned long *)hw_entry);
        break;
      case SWITCH_ACL_TYPE_EGRESS_SYSTEM:
        status = switch_pd_egr_acl_table_delete_entry(
            device, acl_info->direction, *(unsigned long *)hw_entry);
        break;
      default:
        break;
    }
  }
  JLD(ret, intf->entries, ace_handle);
  return status;
}

switch_status_t switch_api_acl_rule_create(
    switch_device_t device,
    switch_handle_t acl_handle,
    unsigned int priority,
    unsigned int key_value_count,
    void *acl_kvp,
    switch_acl_action_t action,
    switch_acl_action_params_t *action_params,
    switch_acl_opt_action_params_t *opt_action_params,
    switch_handle_t *ace) {
  switch_acl_info_t *acl_info = NULL;
  switch_acl_ip_key_value_pair_t *ip_acl = NULL;
  switch_acl_system_key_value_pair_t *system_acl = NULL;
  switch_acl_ipv6_key_value_pair_t *ipv6_acl = NULL;
  switch_acl_mac_key_value_pair_t *mac_acl = NULL;
  switch_acl_egr_key_value_pair_t *egr_acl = NULL;
  unsigned long *jp = NULL;
  void *fields = NULL;
  switch_acl_rule_t *p = NULL;
  tommy_node *node = NULL;
  switch_acl_interface_t *intf = NULL;
  unsigned int i = 0;
  switch_handle_t ace_handle = -1;

  acl_info = switch_acl_get(acl_handle);
  if (!acl_info) {
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  // create an ace entry
  ace_handle = switch_ace_create();
  if (!ace_handle) {
    return SWITCH_STATUS_NO_MEMORY;
  }

  p = switch_ace_get(ace_handle);

  JLI(jp, acl_info->rules, ace_handle);
  if (jp) {
    switch (acl_info->type) {
      case SWITCH_ACL_TYPE_IP:
        ip_acl = (switch_acl_ip_key_value_pair_t *)acl_kvp;
        fields = switch_malloc(
            sizeof(switch_acl_ip_key_value_pair_t) * SWITCH_ACL_IP_FIELD_MAX,
            1);
        if (!fields) {
          return SWITCH_STATUS_NO_MEMORY;
        }
        memset(
            fields,
            0,
            sizeof(switch_acl_ip_key_value_pair_t) * SWITCH_ACL_IP_FIELD_MAX);
        break;
      case SWITCH_ACL_TYPE_SYSTEM:
        system_acl = (switch_acl_system_key_value_pair_t *)acl_kvp;
        fields = switch_malloc(sizeof(switch_acl_system_key_value_pair_t) *
                                   SWITCH_ACL_SYSTEM_FIELD_MAX,
                               1);
        if (!fields) {
          return SWITCH_STATUS_NO_MEMORY;
        }
        memset(fields,
               0,
               sizeof(switch_acl_system_key_value_pair_t) *
                   SWITCH_ACL_SYSTEM_FIELD_MAX);
        break;
      case SWITCH_ACL_TYPE_IPV6:
        ipv6_acl = (switch_acl_ipv6_key_value_pair_t *)acl_kvp;
        fields = switch_malloc(sizeof(switch_acl_ipv6_key_value_pair_t) *
                                   SWITCH_ACL_IPV6_FIELD_MAX,
                               1);
        if (!fields) {
          return SWITCH_STATUS_NO_MEMORY;
        }
        memset(fields,
               0,
               sizeof(switch_acl_ipv6_key_value_pair_t) *
                   SWITCH_ACL_IPV6_FIELD_MAX);
        break;
      case SWITCH_ACL_TYPE_MAC:
        mac_acl = (switch_acl_mac_key_value_pair_t *)acl_kvp;
        fields = switch_malloc(
            sizeof(switch_acl_mac_key_value_pair_t) * SWITCH_ACL_MAC_FIELD_MAX,
            1);
        if (!fields) {
          return SWITCH_STATUS_NO_MEMORY;
        }
        memset(
            fields,
            0,
            sizeof(switch_acl_mac_key_value_pair_t) * SWITCH_ACL_MAC_FIELD_MAX);
        break;
      case SWITCH_ACL_TYPE_EGRESS_SYSTEM:
        egr_acl = (switch_acl_egr_key_value_pair_t *)acl_kvp;
        fields = switch_malloc(
            sizeof(switch_acl_egr_key_value_pair_t) * SWITCH_ACL_EGR_FIELD_MAX,
            1);
        if (!fields) {
          return SWITCH_STATUS_NO_MEMORY;
        }
        memset(
            fields,
            0,
            sizeof(switch_acl_egr_key_value_pair_t) * SWITCH_ACL_EGR_FIELD_MAX);
        break;
      default:
        break;
    }
    if (!fields) {
      return SWITCH_STATUS_NO_MEMORY;
    }
    if (p) {
      memset(p, 0, sizeof(switch_acl_rule_t));
      // walk the list and set the structs
      for (i = 0; i < key_value_count; i++) {
        switch (acl_info->type) {
          case SWITCH_ACL_TYPE_IP:
            *((switch_acl_ip_key_value_pair_t *)fields + i) = ip_acl[i];
            break;
          case SWITCH_ACL_TYPE_SYSTEM:
            *((switch_acl_system_key_value_pair_t *)fields + i) = system_acl[i];
            break;
          case SWITCH_ACL_TYPE_IPV6:
            *((switch_acl_ipv6_key_value_pair_t *)fields + i) = ipv6_acl[i];
            break;
          case SWITCH_ACL_TYPE_MAC:
            *((switch_acl_mac_key_value_pair_t *)fields + i) = mac_acl[i];
            break;
          case SWITCH_ACL_TYPE_EGRESS_SYSTEM:
            *((switch_acl_egr_key_value_pair_t *)fields + i) = egr_acl[i];
            break;
          default:
            break;
        }
      }
      p->acl_handle = acl_handle;
      p->field_count = key_value_count;
      p->fields = fields;
      p->action = action;
      p->action_params = *action_params;
      p->opt_action_params = *opt_action_params;
      p->priority = priority;
    }
    *(unsigned long *)jp = (unsigned long)p;

    // if interface referenced then make the hardware table changes
    if (acl_info->interface_list) {
      node = tommy_list_head(&(acl_info->interface_list));
      while (node) {
        intf = (switch_acl_interface_t *)node->data;
        // update ACL H/W entries
        acl_hw_set(device, acl_info, p, intf, intf->interface, ace_handle);
        node = node->next;
      }
    } else {
      if ((acl_info->type == SWITCH_ACL_TYPE_SYSTEM) ||
          (acl_info->type == SWITCH_ACL_TYPE_EGRESS_SYSTEM)) {
        // update system ACL H/W entries
        acl_hw_set(device, acl_info, p, NULL, 0, ace_handle);
      }
    }
  }
  *ace = ace_handle;
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_acl_rule_delete(switch_device_t device,
                                           switch_handle_t acl_handle,
                                           switch_handle_t ace_handle) {
  switch_acl_info_t *acl_info = NULL;
  switch_acl_rule_t *p = NULL;
  tommy_node *node = NULL;
  unsigned long *jp = NULL;
  switch_acl_interface_t *intf = NULL;
  int ret = 0;
  switch_ace_info_t *ace_info = NULL;

  if (acl_handle == 0) {
    ace_info = switch_ace_get(ace_handle);
    acl_handle = ace_info->acl_handle;
  }

  acl_info = switch_acl_get(acl_handle);
  if (!acl_info) {
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  JLG(jp, acl_info->rules, ace_handle);
  if (jp) {
    p = (switch_acl_rule_t *)(*(unsigned long *)jp);
    JLD(ret, acl_info->rules, ace_handle);
    if (p) {
      // if interface referenced then make the hardware table changes
      if (acl_info->interface_list) {
        node = tommy_list_head(&(acl_info->interface_list));
        while (node) {
          intf = (switch_acl_interface_t *)node->data;
          // update ACL H/W entries
          acl_hw_del(device, acl_info, intf, ace_handle);
          node = node->next;
        }
      } else {
        acl_hw_del(device, acl_info, NULL, ace_handle);
      }
      if (p->fields) {
        switch_free(p->fields);
      }
      switch_ace_delete(ace_handle);
    }
  }
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_acl_renumber(switch_device_t device,
                                        switch_handle_t acl_handle,
                                        int increment_priority) {
  // modify priority in reverse order for priority > 0 or increasing order if
  // walk the list of entries and modify the priority - when supported
  // in pipe_mgr library
  if (increment_priority < 0) {
    // go in ascending order
  } else {
    // go in descending order
  }
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_acl_reference(switch_device_t device,
                                         switch_handle_t acl_handle,
                                         switch_handle_t interface_handle) {
  switch_acl_interface_t *intf = NULL;
  switch_acl_info_t *acl_info = NULL;
  unsigned long *jp = NULL;
  switch_handle_t ace_handle = -1;

  acl_info = switch_acl_get(acl_handle);
  if (!acl_info) {
    return SWITCH_STATUS_INVALID_HANDLE;
  }
  if (acl_info->type == SWITCH_ACL_TYPE_SYSTEM)
    return SWITCH_STATUS_ITEM_ALREADY_EXISTS;

  intf = (switch_acl_interface_t *)switch_malloc(sizeof(switch_acl_interface_t),
                                                 1);
  if (!intf) {
    return SWITCH_STATUS_NO_MEMORY;
  }

  intf->entries = NULL;
  JLL(jp, acl_info->rules, ace_handle);
  while (jp) {
    acl_hw_set(device,
               acl_info,
               (switch_acl_rule_t *)(*(unsigned long *)jp),
               intf,
               interface_handle,
               ace_handle);
    // walk the table
    JLP(jp, acl_info->rules, ace_handle);
  }
  intf->interface = interface_handle;
  tommy_list_insert_head(&(acl_info->interface_list), &(intf->node), intf);
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_acl_remove(switch_device_t device,
                                      switch_handle_t acl_handle,
                                      switch_handle_t interface_handle) {
  switch_acl_info_t *acl_info = NULL;
  switch_acl_interface_t *intf = NULL;
  tommy_node *node = NULL;
  unsigned long *jp = NULL;
  switch_handle_t ace_handle = -1;

  acl_info = switch_acl_get(acl_handle);
  if (!acl_info) {
    return SWITCH_STATUS_INVALID_HANDLE;
  }

  // Delete the rules
  node = tommy_list_head(&(acl_info->interface_list));
  while (node) {
    intf = (switch_acl_interface_t *)node->data;
    if (intf->interface == interface_handle) break;
    node = node->next;
  }
  if (!node) {
    return SWITCH_STATUS_ITEM_NOT_FOUND;
  }
  JLL(jp, acl_info->rules, ace_handle);
  while (jp) {
    acl_hw_del(device, acl_info, intf, ace_handle);
    JLP(jp, acl_info->rules, ace_handle);
  }
  // remove from interface list
  tommy_list_remove_existing(&(acl_info->interface_list), node);
  switch_free(intf);
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_drop_stats_get(switch_device_t device,
                                          int *num_counters,
                                          uint64_t **counters) {
  *num_counters = 256;
  *counters = (uint64_t *)malloc(sizeof(uint64_t) * (*num_counters));
  memset(*counters, 0, sizeof(uint64_t) * (*num_counters));
  switch_pd_drop_stats_get(device, *num_counters, *counters);
  return SWITCH_STATUS_SUCCESS;
}

switch_handle_t switch_api_acl_counter_create(switch_device_t device) {
  switch_handle_t counter_handle = 0;
  unsigned int id = 0;

  id = switch_acl_counter_index_allocate();
  counter_handle = id_to_handle(SWITCH_HANDLE_TYPE_ACL_COUNTER, id);
  return counter_handle;
}

switch_status_t switch_api_acl_counter_delete(switch_device_t device,
                                              switch_handle_t counter_handle) {
  unsigned int id = 0;

  id = handle_to_id(counter_handle);
  switch_pd_acl_stats_reset(device, id);
  switch_acl_counter_index_free(id);
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_acl_stats_get(switch_device_t device,
                                         switch_handle_t counter_handle,
                                         switch_counter_t *counter) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  status =
      switch_pd_acl_stats_get(device, handle_to_id(counter_handle), counter);
  return status;
}

switch_status_t switch_api_acl_stats_reset(switch_device_t device,
                                           switch_handle_t counter_handle) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  status =
      switch_pd_acl_stats_reset(device, handle_to_id(counter_handle));
  return status;
}

switch_acl_type_t switch_acl_type_get(switch_device_t device,
                                      switch_handle_t acl_handle) {
  switch_acl_info_t *acl_info = NULL;
  acl_info = switch_acl_get(acl_handle);
  if (!acl_info) {
    return 0;
  }

  return acl_info->type;
}

switch_handle_t switch_range_handle_create() {
  switch_handle_t range_handle;
  _switch_handle_create(SWITCH_HANDLE_TYPE_RANGE,
                        switch_range_info_t,
                        switch_range_array,
                        NULL,
                        range_handle);
  return range_handle;
}

switch_range_info_t *switch_range_get(switch_handle_t range_handle) {
  switch_range_info_t *range_info = NULL;
  _switch_handle_get(
      switch_range_info_t, switch_range_array, range_handle, range_info);
  return range_info;
}

switch_status_t switch_range_handle_delete(switch_handle_t handle) {
  _switch_handle_delete(switch_range_info_t, switch_range_array, handle);
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_api_acl_range_create(switch_device_t device,
                                            switch_direction_t direction,
                                            switch_range_type_t range_type,
                                            switch_range_t *range,
                                            switch_handle_t *range_handle) {
  switch_range_info_t *range_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  *range_handle = switch_range_handle_create();
  range_info = switch_range_get(*range_handle);
  if (!range_info) {
    SWITCH_API_ERROR("failed to create range handle");
    return SWITCH_STATUS_NO_MEMORY;
  }

  if (range_type == SWITCH_RANGE_TYPE_VLAN ||
      range_type == SWITCH_RANGE_TYPE_PACKET_LENGTH) {
    SWITCH_API_ERROR(
        "failed to create range handle."
        "invalid range type (vlan or packet length)");
    return SWITCH_STATUS_NOT_SUPPORTED;
  }

  if (direction != SWITCH_API_DIRECTION_INGRESS &&
      direction != SWITCH_API_DIRECTION_EGRESS) {
    SWITCH_API_ERROR("failed to create range");
    return SWITCH_STATUS_INVALID_PARAMETER;
  }

  memcpy(&range_info->range, range, sizeof(switch_range_t));
  range_info->range_type = range_type;
  range_info->direction = direction;

  status = switch_pd_range_entry_add(device,
                                     direction,
                                     handle_to_id(*range_handle),
                                     range_type,
                                     range,
                                     &range_info->hw_entry);

  return status;
}

switch_status_t switch_api_acl_range_update(switch_device_t device,
                                            switch_handle_t range_handle,
                                            switch_range_t *range) {
  switch_range_info_t *range_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (!SWITCH_RANGE_HANDLE_VALID(range_handle)) {
    SWITCH_API_ERROR("failed to update range. invalid range handle");
    return SWITCH_STATUS_INVALID_PARAMETER;
  }

  range_info = switch_range_get(range_handle);
  if (!range_info) {
    SWITCH_API_ERROR("failed to update range. invalid range handle");
    return SWITCH_STATUS_INVALID_PARAMETER;
  }

  memcpy(&range_info->range, range, sizeof(switch_range_t));

  status = switch_pd_range_entry_update(device,
                                        range_info->direction,
                                        handle_to_id(range_handle),
                                        range_info->range_type,
                                        range,
                                        range_info->hw_entry);
  return status;
}

switch_status_t switch_api_acl_range_get(switch_device_t device,
                                         switch_handle_t range_handle,
                                         switch_range_t *range) {
  switch_range_info_t *range_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (!SWITCH_RANGE_HANDLE_VALID(range_handle)) {
    SWITCH_API_ERROR("failed to get range. invalid range handle");
    return SWITCH_STATUS_INVALID_PARAMETER;
  }

  range_info = switch_range_get(range_handle);
  if (!range_info) {
    SWITCH_API_ERROR("failed to get range. invalid range handle");
    return SWITCH_STATUS_INVALID_PARAMETER;
  }

  memcpy(range, &range_info->range, sizeof(switch_range_t));

  return status;
}

switch_status_t switch_api_acl_range_delete(switch_device_t device,
                                            switch_handle_t range_handle) {
  switch_range_info_t *range_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (!SWITCH_RANGE_HANDLE_VALID(range_handle)) {
    SWITCH_API_ERROR("failed to delete range. invalid range handle");
    return SWITCH_STATUS_INVALID_PARAMETER;
  }

  range_info = switch_range_get(range_handle);
  if (!range_info) {
    SWITCH_API_ERROR("failed to delete range. invalid range handle");
    return SWITCH_STATUS_INVALID_PARAMETER;
  }

  status = switch_pd_range_entry_delete(device,
                                        range_info->direction,
                                        range_info->range_type,
                                        range_info->hw_entry);

  if (status != SWITCH_STATUS_SUCCESS) {
    SWITCH_API_ERROR("failed to delete range. pd delete failed");
    return status;
  }

  switch_range_handle_delete(range_handle);

  return status;
}

switch_status_t switch_api_acl_range_type_get(switch_device_t device,
                                              switch_handle_t range_handle,
                                              switch_range_type_t *range_type) {
  switch_range_info_t *range_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  if (!SWITCH_RANGE_HANDLE_VALID(range_handle)) {
    SWITCH_API_ERROR("failed to get range type. invalid range handle");
    return SWITCH_STATUS_INVALID_PARAMETER;
  }

  range_info = switch_range_get(range_handle);
  if (!range_info) {
    SWITCH_API_ERROR("failed to get range type. invalid range handle");
    return SWITCH_STATUS_INVALID_PARAMETER;
  }

  *range_type = range_info->range_type;

  return status;
}

#ifdef __cplusplus
}
#endif
