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

#ifndef _switch_mcast_h_
#define _switch_mcast_h_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @defgroup MULTICAST Multicast API
 *  API functions listed to create/delete multicast trees and to add/delete multicast routes MFIB
 *  @{
 The multicast API's are controlled based on the multicast protocols that propagates the route entries
 to MFIB. A multicast tree handle is programmed against each route in mfib. The tree is derived in the queuing block
 and the packet is replicated based on the members.
 */ // begin of MCAST
 // MCAST
 
/* MCAST API's */
/**
  Create a Multicast Tree
  @param device - device that programs the tree
*/
switch_handle_t switch_api_multicast_tree_create(switch_device_t device);

/**
  Delete a multicast tree
  @param device - device that programs the tree
  @param mgid_handle - Handle that uniquely identifies multicast tree
*/
switch_status_t switch_api_multicast_tree_delete(switch_device_t device, switch_handle_t mgid_handle);

/**
 Add a list of members to multicast tree
 @param device - device that programs the tree
 @param mgid_handle - Handle that uniquely identifies multicast tree
 @param vlan_handle - Handle that uniquely identifies a vlan.
 @param intf_handle_count - Count of interface members
 @param interface_handle - List of interfaces to be added to multicast tree
*/
switch_status_t switch_api_multicast_member_add(switch_device_t device,
                                        switch_handle_t mgid_handle,
                                        switch_handle_t vlan_handle,
                                        uint16_t intf_handle_count,
                                        switch_handle_t *interface_handle);

/**
 Delete a list of members to multicast tree
 @param device - device that programs the tree
 @param mgid_handle - Handle that uniquely identifies multicast tree
 @param vlan_handle - Handle that uniquely identifies a vlan.
 @param intf_handle_count - Count of interface members
 @param interface_handle - List of interfaces to be deleted from multicast tree
*/
switch_status_t switch_api_multicast_member_delete(switch_device_t device,
                                           switch_handle_t mgid_handle,
                                           switch_handle_t vlan_handle,
                                           uint16_t intf_handle_count,
                                           switch_handle_t *interface_handle);

/** @} */ // end of mcast API

#ifdef __cplusplus
}
#endif

#endif
