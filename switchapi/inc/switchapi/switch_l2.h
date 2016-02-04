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

#ifndef _switch_l2_h_
#define _switch_l2_h_

#include <stdio.h>

#include "switch_base_types.h"
#include "switch_handle.h"
#include "switch_interface.h"
#include "switch_status.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
/** @defgroup Switching L2 Switching API
 *  API functions listed to configure Mac Address tables
 *  @{
 The basic switching APIs are controlled by the manipulation of the MAC tables – source and destination.
 Addresses learnt from packets on a port and/or VLAN are used to switch packets destined that address within the VLAN.
 */ // begin of L2
 // L2

/** Mac entry type */
typedef enum switch_mac_entry_type_ {
    SWITCH_MAC_ENTRY_UNSPECIFIED,
    SWITCH_MAC_ENTRY_DYNAMIC,
    SWITCH_MAC_ENTRY_STATIC
} switch_mac_entry_type_t;

/** Mac event */
typedef enum switch_mac_event_ {
    SWITCH_MAC_EVENT_UNSPECIFIED,
    SWITCH_MAC_EVENT_LEARNED,
    SWITCH_MAC_EVENT_AGED,
    SWITCH_MAC_EVENT_FLUSHED
} switch_mac_event_t;

/** Mac attributes */
typedef enum switch_mac_attr_ {
    SWITCH_MAC_ATTR_AGING_TIME,
    SWITCH_MAC_ATTR_TABLE_SIZE,

    SWITCH_MAC_ATTR_CUSTOM_RANGE_BASE = 0x10000000
} switch_mac_attr_t;

/** Mac action */
typedef enum switch_mac_action_ {
    SWITCH_MAC_ACTION_DROP,
    SWITCH_MAC_ACTION_FORWARD
} switch_mac_action_t;

/** Mac entry */
typedef struct switch_api_mac_entry_ {
    switch_handle_t vlan_handle;                                 /**< vlan handle */
    switch_mac_addr_t mac;                                       /**< mac address */
    switch_handle_t handle;                                      /**< Interface or nexthop handle */
    switch_mac_entry_type_t entry_type;                          /**< entry type */
    switch_mac_action_t mac_action;                              /**< mac action */
} switch_api_mac_entry_t;

/**
 learn notification callback function pointer
 @param mac_entries - set of mac entries
*/
typedef void (*switch_mac_learn_entry_notify_cb)(switch_api_mac_entry_t *mac_entry);

/**
 learn notification callback function pointer
 @param mac_entries - set of mac entries
*/
typedef void (*switch_mac_aging_entry_notify_cb)(switch_api_mac_entry_t *mac_entry);

/** Learn and aging call back functions */
typedef struct switch_mac_cb_fn_ {
    switch_mac_learn_entry_notify_cb mac_learn_notify_cb;       /**< mac learn notification callback */
    switch_mac_aging_entry_notify_cb mac_aging_notify_cb;       /**< mac aging notification callback */
} switch_mac_cb_fn_t;

/**
 Add Destination MAC entry
 @param device - device
 @param mac_entry - contains the vlan and mac that has to be programmed
*/
switch_status_t switch_api_mac_table_entry_add(switch_device_t device,
                                       switch_api_mac_entry_t *mac_entry);

/**
 Add a set of Destination MAC table entries.
 @param device- device
 @param mac_entry_count - Number of mac entries to be added
 @param mac_entries - list of entries contains the vlan and mac that has
 to be programmed
*/
switch_status_t switch_api_mac_table_entries_add(switch_device_t device, uint16_t mac_entry_count,
                                         switch_api_mac_entry_t *mac_entries);

/**
 Update Destination MAC entry
 @param device - device
 @param mac_entry - contains the vlan and mac that has to be programmed
*/
switch_status_t switch_api_mac_table_entry_update(switch_device_t device,
                                          switch_api_mac_entry_t *mac_entry);

/**
 Update a set of Destination MAC table entries. 
 @param device - device
 @param mac_entry_count - Number of mac entries to be updated
 @param mac_entries - list of entries contains the vlan and mac that has
 to be programmed
*/
switch_status_t switch_api_mac_table_entries_update(switch_device_t device, uint16_t mac_entry_count,
                                            switch_api_mac_entry_t *mac_entries);

/**
 Delete a Destination MAC entry.
 @param device - device
 @param mac_entry - contains the vlan and mac that has to be deleted
*/
switch_status_t switch_api_mac_table_entry_delete(switch_device_t device,
                                          switch_api_mac_entry_t *mac_entry);

/**
 Delete a set of destination mac table entries. 
 @param device - device
 @param mac_entries - list of entries contains the vlan and mac that has
 to be deleted
 @param mac_entry_count - Number of mac entries to be deleted
 */
switch_status_t switch_api_mac_table_entries_delete(switch_device_t device,
                                                    uint16_t mac_entry_count,
                                                    switch_api_mac_entry_t *mac_entries);
/**
  Delete all Destination MAC entries from FDB.
 @param device - device
*/
switch_status_t switch_api_mac_table_entries_delete_all(switch_device_t device);

/**
 Delete all MACs on a given outgoing intf
 @param device - device
 @param interface_handle outgoing interface handle
*/
switch_status_t switch_api_mac_table_entries_delete_by_interface(switch_device_t device,
                                                                 switch_handle_t interface_handle);

/**
 Delete all MACs on a selected VLAN
 @param device - device
 @param vlan_handle idenifes the VLAN (domain)
*/
switch_status_t switch_api_mac_table_entries_delete_by_vlan(switch_device_t device,
                                                            switch_handle_t vlan_handle);

/**
 Delete all MACs on a selected VLAN + Interface
 @param device - device
 @param handle idenfies the interface/port/lag
 @param vlan_handle idenifes the VLAN (domain)
*/
switch_status_t switch_api_mac_table_entries_delete_by_interface_vlan(switch_device_t device,
                                                                      switch_handle_t handle,
                                                                      switch_handle_t vlan_handle);

/**
 Register a calback function for mac learning
 @param cb_fn - function to be called when a mac is learnt
*/
switch_status_t switch_api_mac_register_learning_callback(switch_mac_learn_entry_notify_cb cb_fn);

/**
 Register a calback function for mac aging
 @param cb_fn - function to be called when a mac is aged
*/
switch_status_t switch_api_mac_register_aging_callback(switch_mac_aging_entry_notify_cb cb_fn);

/**
  Set global attribute for mac table
  @param mac_attr- Attribute type
  @param value - value of the attribute
*/
switch_status_t switch_api_mac_table_attribute_set(switch_mac_attr_t mac_attr, uint64_t value);

/**
  Get global attribute of mac table
  @param mac_attr - Attribute type
  @param value - value of the attribute
*/
switch_status_t switch_api_mac_table_attribute_get(switch_mac_attr_t mac_attr, uint64_t *value);

/**
  Set mac aging time of mac table
  @param value - value of aging time
*/
switch_status_t switch_api_mac_table_aging_time_set(uint64_t value);

/**
  Get mac aging time of mac table
  @param value - value of aging time
*/
switch_status_t switch_api_mac_table_aging_time_get(uint64_t *value);

/**
 Register a iterator function to walk through all the mac entries
 @param mac_entry - Mac entry
 */
typedef switch_status_t (*switch_mac_table_iterator_fn)(switch_api_mac_entry_t *mac_entry);

/**
 Calls the iterator function for every mac entry
 @param iterator_fn - Iterator function
 */
switch_status_t switch_api_mac_table_entries_get(switch_mac_table_iterator_fn iterator_fn);

/**
 Calls the iterator function for every mac entry on vlan
 @param vlan_handle - Handle of vlan
 @param iterator_fn - Iterator function
 */
switch_status_t switch_api_mac_table_entries_get_by_vlan(switch_handle_t vlan_handle,
                                           switch_mac_table_iterator_fn iterator_fn);

/**
 Calls the iterator function for every mac entry on interface
 @param intf_handle - Interface handle
 @param iterator_fn - Iterator function
 */
switch_status_t switch_api_mac_table_entries_get_by_interface(switch_handle_t intf_handle,
                                           switch_mac_table_iterator_fn iterator_fn);

/**
 Calls the iterator function for every mac entry on interface and vlan
 @param intf_handle - Interface handle
 @param vlan_handle - idenifes the VLAN (domain)
 @param iterator_fn - Iterator function
 */
switch_status_t switch_api_mac_table_entries_get_by_interface_vlan(switch_handle_t intf_handle,
                        switch_handle_t vlan_handle, switch_mac_table_iterator_fn iterator_fn);

/**
 Set the learning buffer timeout value
 @param device device
 @param timeout - Timeout in milliseconds
 */
switch_status_t switch_api_mac_table_set_learning_timeout(switch_device_t device, uint32_t timeout);

/**
 Dump mac table
 */
switch_status_t switch_api_mac_table_print_all();

/** @} */ // end of L2
    
#ifdef __cplusplus
}
#endif

#endif /* defined(__switch_api__switch_l2__) */
