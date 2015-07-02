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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static void *switch_acl_array;

switch_status_t
switch_acl_init(switch_device_t device)
{
    switch_acl_array = NULL;
    switch_handle_type_init(SWITCH_HANDLE_TYPE_ACL, (4*1024));
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_acl_free(switch_device_t device)
{
    switch_handle_type_free(SWITCH_HANDLE_TYPE_ACL);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_acl_create()
{
    switch_handle_t acl_handle;
    _switch_handle_create(SWITCH_HANDLE_TYPE_ACL, switch_acl_info_t, switch_acl_array, NULL, acl_handle);
    return acl_handle;
}

switch_acl_info_t *
switch_acl_get(switch_handle_t acl_handle)
{
    switch_acl_info_t *acl_info = NULL;
    _switch_handle_get(switch_acl_info_t, switch_acl_array, acl_handle, acl_info);
    return acl_info;
}

switch_status_t
switch_acl_delete(switch_handle_t handle)
{
    _switch_handle_delete(switch_acl_info_t, switch_acl_array, handle);
    return SWITCH_STATUS_SUCCESS;
}

switch_handle_t
switch_api_acl_list_create(switch_device_t device, switch_acl_type_t type)
{
    switch_acl_info_t                 *acl_info = NULL;
    switch_handle_t                    acl_handle;

    acl_handle = switch_acl_create();
    acl_info = switch_acl_get(acl_handle);
    if (!acl_info) {
        return SWITCH_STATUS_NO_MEMORY;
    }
    acl_info->type = type;
    acl_info->rules = NULL;
    tommy_list_init(&(acl_info->interface_list));
    return acl_handle;
}

switch_status_t
switch_api_acl_list_delete(switch_device_t device, switch_handle_t acl_handle)
{
    switch_acl_info_t *acl_info = NULL;
    
    acl_info = switch_acl_get(acl_handle);
    if (!acl_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }
    switch_acl_delete(acl_handle);
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t
switch_acl_ip_set_fields_actions(switch_device_t device, switch_acl_rule_t *p,
                                 switch_handle_t interface_handle, p4_pd_entry_hdl_t *entry)
{
    switch_acl_ip_key_value_pair_t    *ip_acl = NULL;
    switch_interface_info_t           *intf_info = NULL;
    uint16_t                           bd_label = 0;
    uint16_t                           if_label = 0;
    switch_status_t                    status = SWITCH_STATUS_SUCCESS;

    if (interface_handle) {
        intf_info = switch_api_interface_get(interface_handle);
        if (!intf_info) {
            return SWITCH_STATUS_INVALID_INTERFACE;
        }
        switch(switch_handle_get_type(interface_handle)) {
            case SWITCH_HANDLE_TYPE_INTERFACE:
                if_label = intf_info->api_intf_info.u.port_lag_handle;
                break;
            case SWITCH_HANDLE_TYPE_BD:
                bd_label = handle_to_id(interface_handle);;
                break; 
            default:
                return SWITCH_STATUS_INVALID_HANDLE;
        }
    }
    ip_acl = (switch_acl_ip_key_value_pair_t *)p->fields;

    status = switch_pd_ipv4_acl_table_add_entry(device, if_label, bd_label, p->priority,
                                         ip_acl, p->action, entry);
    return status;
}

static switch_status_t
switch_acl_ipv6_set_fields_actions(switch_device_t device, switch_acl_rule_t *p,
                                   switch_handle_t interface_handle, p4_pd_entry_hdl_t *entry)
{
    switch_acl_ipv6_key_value_pair_t  *ipv6_acl=NULL;
    switch_interface_info_t           *intf_info = NULL;
    uint16_t                          bd_label = 0;
    uint16_t                          if_label = 0;
    switch_status_t                   status = SWITCH_STATUS_SUCCESS;

    if (interface_handle) {
        intf_info = switch_api_interface_get(interface_handle);
        if (!intf_info) {
            return SWITCH_STATUS_INVALID_INTERFACE;
        }
        switch(switch_handle_get_type(interface_handle)) {
            case SWITCH_HANDLE_TYPE_INTERFACE:
                if_label = intf_info->api_intf_info.u.port_lag_handle;
                break;
            case SWITCH_HANDLE_TYPE_BD:
                bd_label = handle_to_id(interface_handle);;
                break; 
            default:
                return SWITCH_STATUS_INVALID_HANDLE;
        }
    }
    ipv6_acl = (switch_acl_ipv6_key_value_pair_t *)p->fields;
    status = switch_pd_ipv6_acl_table_add_entry(device, if_label, bd_label, p->priority,
                                           ipv6_acl, p->action, entry);
    return status;
}

static switch_status_t
switch_acl_mac_set_fields_actions(switch_device_t device, switch_acl_rule_t *p,
                                  switch_handle_t interface_handle, p4_pd_entry_hdl_t *entry)
{
    switch_acl_mac_key_value_pair_t             *mac_acl=NULL;
    switch_interface_info_t                     *intf_info = NULL;
    uint16_t                                     bd_label = 0;
    uint16_t                                     if_label = 0;
    switch_status_t                              status = SWITCH_STATUS_SUCCESS;

    if (interface_handle) {
        intf_info = switch_api_interface_get(interface_handle);
        if (!intf_info) {
            return SWITCH_STATUS_INVALID_INTERFACE;
        }
        switch(switch_handle_get_type(interface_handle)) {
            case SWITCH_HANDLE_TYPE_INTERFACE:
                if_label = intf_info->api_intf_info.u.port_lag_handle;
                break;
            case SWITCH_HANDLE_TYPE_BD:
                bd_label = handle_to_id(interface_handle);;
                break; 
            default:
                return SWITCH_STATUS_INVALID_HANDLE;
        }
    }

    mac_acl = (switch_acl_mac_key_value_pair_t *)p->fields;
    status = switch_pd_mac_acl_table_add_entry(device, if_label, bd_label, p->priority,
                                          mac_acl, p->action, entry);
    return status;
}

static switch_status_t
switch_acl_ip_racl_set_fields_actions(switch_device_t device, switch_acl_rule_t *p,
                                      switch_handle_t interface_handle, p4_pd_entry_hdl_t *entry)
{
    switch_acl_ip_racl_key_value_pair_t         *ip_racl = NULL;
    uint16_t                                     bd_label = 0;
    uint16_t                                     if_label = 0;
    switch_status_t                              status = SWITCH_STATUS_SUCCESS;

    if(interface_handle) {
        switch(switch_handle_get_type(interface_handle)) {
            case SWITCH_HANDLE_TYPE_BD:
                bd_label = handle_to_id(interface_handle);;
                break; 
            default:
                return SWITCH_STATUS_INVALID_HANDLE;
        }
    }
    ip_racl = (switch_acl_ip_racl_key_value_pair_t *)p->fields;
    status = switch_pd_ipv4_racl_table_add_entry(device, if_label, bd_label, p->priority,
                                          ip_racl, p->action, entry);
    return status;
}

static switch_status_t
switch_acl_ipv6_racl_set_fields_actions(switch_device_t device, switch_acl_rule_t *p,
                                        switch_handle_t interface_handle, p4_pd_entry_hdl_t *entry)
{
    switch_acl_ipv6_racl_key_value_pair_t       *ipv6_racl=NULL;
    uint16_t                                     bd_label = 0;
    uint16_t                                     if_label = 0;
    switch_status_t                              status = SWITCH_STATUS_SUCCESS;

    if(interface_handle) {
        switch(switch_handle_get_type(interface_handle)) {
            case SWITCH_HANDLE_TYPE_BD:
                bd_label = handle_to_id(interface_handle);;
                break; 
            default:
                return SWITCH_STATUS_INVALID_HANDLE;
                break; 
        }
    }
    ipv6_racl = (switch_acl_ipv6_racl_key_value_pair_t *)p->fields;
    status = switch_pd_ipv6_racl_table_add_entry(device, if_label, bd_label, p->priority,
                                            ipv6_racl, p->action, entry);
    return status;
}

static switch_status_t
switch_acl_qos_set_fields_actions(switch_device_t device, switch_acl_rule_t *p,
                                  switch_handle_t interface_handle, p4_pd_entry_hdl_t *entry)
{
    switch_acl_qos_key_value_pair_t             *qos_acl = NULL;
    switch_interface_info_t                     *intf_info = NULL;
    uint16_t                                     bd_label = 0;
    uint16_t                                     if_label = 0;
    switch_status_t                              status = SWITCH_STATUS_SUCCESS;

    if (interface_handle) {
        intf_info = switch_api_interface_get(interface_handle);
        if (!intf_info) {
            return SWITCH_STATUS_INVALID_INTERFACE;
        }
        switch(switch_handle_get_type(interface_handle)) {
            case SWITCH_HANDLE_TYPE_INTERFACE:
                if_label = handle_to_id(interface_handle);
                break;
            default:
                return SWITCH_STATUS_INVALID_HANDLE;
        }
    }
    qos_acl = (switch_acl_qos_key_value_pair_t *)p->fields;
    status = switch_pd_qos_acl_table_add_entry(device, if_label, bd_label, p->priority,
                                          qos_acl, p->action, entry);
    return status;
}

static switch_status_t
switch_acl_system_set_fields_actions(switch_device_t device, switch_acl_rule_t *p,
                                     switch_handle_t interface_handle, p4_pd_entry_hdl_t *entry)
{
    switch_acl_system_key_value_pair_t          *system_acl = NULL;
    switch_interface_info_t                     *intf_info = NULL;
    uint16_t                                     bd_label = 0;
    uint16_t                                     if_label = 0;
    switch_status_t                              status = SWITCH_STATUS_SUCCESS;

    if (interface_handle) {
        intf_info = switch_api_interface_get(interface_handle);
        if (!intf_info) {
            return SWITCH_STATUS_INVALID_INTERFACE;
        }
        switch(switch_handle_get_type(interface_handle)) {
            case SWITCH_HANDLE_TYPE_INTERFACE:
                if_label = intf_info->api_intf_info.u.port_lag_handle;
                break;
            case SWITCH_HANDLE_TYPE_BD:
                bd_label = handle_to_id(interface_handle);;
                break; 
            default:
                return SWITCH_STATUS_INVALID_HANDLE;
        }
    }
    system_acl = (switch_acl_system_key_value_pair_t *)p->fields;
    status = switch_pd_system_acl_table_add_entry(device, if_label, bd_label, p->priority,
                                            system_acl, p->action, &p->action_params, entry);
    return status;
}

static switch_status_t
acl_hw_set(switch_device_t device, switch_acl_info_t *acl_info,
           switch_acl_rule_t *p, switch_acl_interface_t *intf,
           switch_handle_t interface_handle, Word_t index)
{
    p4_pd_entry_hdl_t                           entry;
    switch_status_t                             status =  SWITCH_STATUS_SUCCESS;
    unsigned long                              *hw_entry = NULL;

    switch (acl_info->type) {
        case SWITCH_ACL_TYPE_SYSTEM:
            status = switch_acl_system_set_fields_actions(device, p, interface_handle, &entry);
            break;
        case SWITCH_ACL_TYPE_IP:
            status = switch_acl_ip_set_fields_actions(device, p, interface_handle, &entry);
            break;
        case SWITCH_ACL_TYPE_IPV6:
            status = switch_acl_ipv6_set_fields_actions(device, p, interface_handle, &entry);
            break;
        case SWITCH_ACL_TYPE_IP_RACL:
            status = switch_acl_ip_racl_set_fields_actions(device, p, interface_handle, &entry);
            break;
        case SWITCH_ACL_TYPE_IPV6_RACL:
            status = switch_acl_ipv6_racl_set_fields_actions(device, p, interface_handle, &entry);
            break;
        case SWITCH_ACL_TYPE_MAC:
            status = switch_acl_mac_set_fields_actions(device, p, interface_handle, &entry);
            break;
        case SWITCH_ACL_TYPE_QOS:
            status = switch_acl_qos_set_fields_actions(device, p, interface_handle, &entry);
            break;
        default:
            break;
    }

    if (intf) {
        // use the index from rule list in the interface entries
        JLI(hw_entry, intf->entries, index);
        *(unsigned long *)hw_entry = entry;
    }
    return status;
}

static switch_status_t
acl_hw_del(switch_device_t device, switch_acl_info_t *acl_info,
           switch_acl_interface_t *intf, Word_t index)
{
    unsigned long                              *hw_entry = NULL;
    int                                         ret = 0;
    switch_status_t                             status = SWITCH_STATUS_SUCCESS;

    JLG(hw_entry, intf->entries, index);

    switch(acl_info->type) {
        case SWITCH_ACL_TYPE_SYSTEM:
            status = switch_pd_system_acl_table_delete_entry(device, *(unsigned long *) hw_entry);
            break;
        case SWITCH_ACL_TYPE_IP:
            status = switch_pd_ipv4_acl_table_delete_entry(device, *(unsigned long *) hw_entry);
            break;
        case SWITCH_ACL_TYPE_IPV6:
            status = switch_pd_ipv6_acl_table_delete_entry(device, *(unsigned long *) hw_entry);
            break;
        case SWITCH_ACL_TYPE_IP_RACL:
            status = switch_pd_ipv4_racl_table_delete_entry(device, *(unsigned long *) hw_entry);
            break;
        case SWITCH_ACL_TYPE_IPV6_RACL:
            status = switch_pd_ipv6_racl_table_delete_entry(device, *(unsigned long *) hw_entry);
            break;
        case SWITCH_ACL_TYPE_MAC:
            status = switch_pd_mac_acl_table_delete_entry(device, *(unsigned long *) hw_entry);
            break;
        case SWITCH_ACL_TYPE_QOS:
            status = switch_pd_qos_acl_table_delete_entry(device, *(unsigned long *) hw_entry);
            break;
        default:
            break;
    }

    JLD(ret, intf->entries, index);
    return status;
}

switch_status_t
switch_api_acl_rule_create(switch_device_t device, switch_handle_t acl_handle,
                           unsigned int priority, unsigned int key_value_count,
                           void *acl_kvp, switch_acl_action_t action,
                           switch_acl_action_params_t *action_params)
{
    switch_acl_info_t                           *acl_info = NULL;
    switch_acl_ip_key_value_pair_t              *ip_acl = NULL;
    switch_acl_system_key_value_pair_t          *system_acl = NULL;
    switch_acl_ipv6_key_value_pair_t            *ipv6_acl  =NULL;
    switch_acl_mac_key_value_pair_t             *mac_acl = NULL;
    unsigned long                               *jp = NULL;
    void                                        *fields = NULL;
    switch_acl_rule_t                           *p = NULL;
    tommy_node                                  *node = NULL;
    switch_acl_interface_t                      *intf = NULL;
    int                                          i = 0;

    acl_info = switch_acl_get(acl_handle);
    if (!acl_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    JLI(jp, acl_info->rules, priority);
    if (jp) {
        switch (acl_info->type) {
            case SWITCH_ACL_TYPE_IP:
                ip_acl = (switch_acl_ip_key_value_pair_t *)acl_kvp;
                fields = switch_malloc(sizeof(switch_acl_ip_key_value_pair_t )*SWITCH_ACL_IP_FIELD_MAX, 1);
                memset(fields, 0, sizeof(switch_acl_ip_key_value_pair_t )*SWITCH_ACL_IP_FIELD_MAX);
                break;
            case SWITCH_ACL_TYPE_SYSTEM:
                system_acl = (switch_acl_system_key_value_pair_t *)acl_kvp;
                fields = switch_malloc(sizeof(switch_acl_system_key_value_pair_t )*SWITCH_ACL_SYSTEM_FIELD_MAX, 1);
                memset(fields, 0, sizeof(switch_acl_system_key_value_pair_t )*SWITCH_ACL_SYSTEM_FIELD_MAX);
                break;
            case SWITCH_ACL_TYPE_IPV6:
                ipv6_acl = (switch_acl_ipv6_key_value_pair_t *)acl_kvp;
                fields = switch_malloc(sizeof(switch_acl_ipv6_key_value_pair_t )*SWITCH_ACL_IPV6_FIELD_MAX, 1);
                memset(fields, 0, sizeof(switch_acl_ipv6_key_value_pair_t )*SWITCH_ACL_IPV6_FIELD_MAX);
                break;
            case SWITCH_ACL_TYPE_MAC:
                mac_acl = (switch_acl_mac_key_value_pair_t *)acl_kvp;
                fields = switch_malloc(sizeof(switch_acl_mac_key_value_pair_t )*SWITCH_ACL_MAC_FIELD_MAX, 1);
                memset(fields, 0, sizeof(switch_acl_mac_key_value_pair_t )*SWITCH_ACL_MAC_FIELD_MAX);
                break;
            default:
                break;
        }
        if (!fields) {
            return SWITCH_STATUS_NO_MEMORY;
        }
        p = switch_malloc(sizeof(switch_acl_rule_t), 1);
        if (p) {
            memset(p, 0, sizeof(switch_acl_rule_t));
            // walk the list and set the structs
            for (i=0;i<key_value_count;i++) {
                switch (acl_info->type) {
                    case SWITCH_ACL_TYPE_IP:
                        *((switch_acl_ip_key_value_pair_t  *)fields + ip_acl[i].field) = ip_acl[i];
                        break;
                    case SWITCH_ACL_TYPE_SYSTEM:
                        *((switch_acl_system_key_value_pair_t  *)fields + system_acl[i].field) = system_acl[i];
                        break;
                    case SWITCH_ACL_TYPE_IPV6:
                        *((switch_acl_ipv6_key_value_pair_t  *)fields + ipv6_acl[i].field) = ipv6_acl[i];
                        break;
                    case SWITCH_ACL_TYPE_MAC:
                        *((switch_acl_mac_key_value_pair_t  *)fields + mac_acl[i].field) = mac_acl[i];
                        break;
                    default:
                        break;
                 }
            }
            p->fields = fields;
            p->action = action;
            p->action_params = *action_params;
        }
        p->priority = priority;
        *(unsigned long *)jp = (unsigned long)p;

        // if interface referenced then make the hardware table changes
        if (acl_info->interface_list) {
            node = tommy_list_head(&(acl_info->interface_list));
            while (node) {
                intf = node->data;
                // update ACL H/W entries
                acl_hw_set(device, acl_info, p, intf, intf->interface, priority);
                node = node->next;
            }
        } else {
            if (acl_info->type == SWITCH_ACL_TYPE_SYSTEM) {
                // update system ACL H/W entries
                acl_hw_set(device, acl_info, p, NULL, 0, priority);
            }
        }
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_acl_rule_delete(switch_device_t device,
                           switch_handle_t acl_handle,
                           unsigned int priority)
{
    switch_acl_info_t                           *acl_info = NULL;
    switch_acl_rule_t                           *p = NULL;
    tommy_node                                  *node = NULL;
    unsigned long                               *jp = NULL;
    switch_acl_interface_t                      *intf = NULL;
    int                                          ret = 0;

    acl_info = switch_acl_get(acl_handle);
    if (!acl_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    JLG(jp, acl_info->rules, priority);
    if (jp) {
        p = (switch_acl_rule_t *) (*(unsigned long *)jp);
        JLD(ret, acl_info->rules, priority);
        if (p) {
            // if interface referenced then make the hardware table changes
            if (acl_info->interface_list) {
                node = tommy_list_head(&(acl_info->interface_list));
                while (node) {
                    intf = node->data;
                    // update ACL H/W entries
                    acl_hw_del(device, acl_info, intf, priority);
                    node = node->next;
                }
            }
            if (p->fields) {
                switch_free(p->fields);
            }
            switch_free(p);
        }
    }
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_acl_renumber(switch_device_t device,
                        switch_handle_t acl_handle,
                        int increment_priority)
{
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

switch_status_t
switch_api_acl_reference(switch_device_t device,
                         switch_handle_t acl_handle,
                         switch_handle_t interface_handle)
{
    switch_acl_interface_t            *intf = NULL;
    switch_acl_info_t                 *acl_info = NULL;
    unsigned long                     *jp = NULL;
    Word_t                             index = -1;

    acl_info = switch_acl_get(acl_handle);
    if (!acl_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    intf = switch_malloc(sizeof(switch_acl_interface_t), 1);
    if (!intf) {
        return SWITCH_STATUS_NO_MEMORY;
    }

    intf->entries = NULL;
    JLL(jp, acl_info->rules, index);
    while (jp) {
       acl_hw_set(device, acl_info, (switch_acl_rule_t *)(*(unsigned long *)jp), intf, interface_handle, index);
       // walk the table
       JLP(jp, acl_info->rules, index);
    }
    intf->interface = interface_handle;
    tommy_list_insert_head(&(acl_info->interface_list), &(intf->node), intf);
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t
switch_api_acl_remove(switch_device_t device, 
                      switch_handle_t acl_handle,
                      switch_handle_t interface_handle)
{
    switch_acl_info_t                 *acl_info = NULL;
    switch_acl_interface_t            *intf = NULL;
    tommy_node                        *node = NULL;
    unsigned long                     *jp = NULL;
    Word_t                             index = -1;

    acl_info = switch_acl_get(acl_handle);
    if (!acl_info) {
        return SWITCH_STATUS_INVALID_HANDLE;
    }

    // Delete the rules
    node = tommy_list_head(&(acl_info->interface_list));
    while (node) {
        intf = node->data;
        if (intf->interface == interface_handle)
            break;
        node = node->next;
    }
    if(!node) {
        return SWITCH_STATUS_ITEM_NOT_FOUND;
    }
    JLL(jp, acl_info->rules, index);
    while (jp) {
        acl_hw_del(device, acl_info, intf, index);
        JLP(jp, acl_info->rules, index);
    }
    // remove from interface list
    tommy_list_remove_existing(&(acl_info->interface_list), node);
    switch_free(intf);
    return SWITCH_STATUS_SUCCESS;
}

#ifdef __cplusplus
}
#endif
