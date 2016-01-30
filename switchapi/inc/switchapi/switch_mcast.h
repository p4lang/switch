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

/** Multicast mode */
typedef enum switch_mcast_mode_ {
    SWITCH_API_MCAST_IPMC_NONE,
    SWITCH_API_MCAST_IPMC_PIM_SM,
    SWITCH_API_MCAST_IPMC_PIM_BIDIR
} switch_mcast_mode_t;

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
 @param mbr_count - Count of members
 @param mbrs - List of interfaces to be added to multicast tree
*/
switch_status_t switch_api_multicast_member_add(switch_device_t device,
                                        switch_handle_t mgid_handle,
                                        uint16_t mbr_count,
                                        switch_vlan_interface_t *mbrs);

/**
 Delete a list of members to multicast tree
 @param device - device that programs the tree
 @param mgid_handle - Handle that uniquely identifies multicast tree
 @param mbr_count - Count of members
 @param mbrs - List of interfaces to be deleted from multicast tree
*/
switch_status_t switch_api_multicast_member_delete(switch_device_t device,
                                        switch_handle_t mgid_handle,
                                        uint16_t mbr_count,
                                        switch_vlan_interface_t *mbrs);

/**
 Get the list of members of a multicast tree
 @param device - device that programs the tree
 @param mgid_handle - Handle that uniquely identifies multicast tree
 @param mbr_count - Count of members
 @param mbrs - List of interfaces part of the multicast tree
*/
switch_status_t switch_api_multicast_member_get(switch_device_t device,
                                        switch_handle_t mgid_handle,
                                        uint16_t *mbr_count,
                                        switch_vlan_interface_t **mbrs);

/**
 Add a (S,G) or (*, G) entry to MFIB.
 @param device - device that programs the tree
 @param mgid_handle - Handle that uniquely identifies multicast tree
 @param vrf_handle - VRF handle
 @param src_ip - Source IP address
 @param grp_ip - Group IP address
 @param mc_mode - Multicast mode to indicate PIM SM/PIM BIDIR
 @param rpf_vlan_list - List of RPF vlan handles
 @param rpf_vlan_count - Count of RPF vlan's
*/
switch_status_t switch_api_multicast_mroute_add(switch_device_t device,
                                        switch_handle_t mgid_handle,
                                        switch_handle_t vlan_vrf_handle,
                                        const switch_ip_addr_t *src_ip,
                                        const switch_ip_addr_t *grp_ip,
                                        switch_mcast_mode_t mc_mode,
                                        switch_handle_t *rpf_vlan_list,
                                        uint16_t rpf_vlan_count);

/**
 Delete a (S,G) or (*, G) entry from MFIB.
 @param device - device that programs the tree
 @param vrf_handle - VRF handle
 @param src_ip - Source IP address
 @param grp_ip - Group IP address
*/
switch_status_t switch_api_multicast_mroute_delete(switch_device_t device,
                                        switch_handle_t vrf_handle,
                                        const switch_ip_addr_t *src_ip,
                                        const switch_ip_addr_t *grp_ip);

/**
 For a (S,G) or (*, G) get the multicast tree
 @param device - device that programs the tree
 @param vrf_handle - VRF handle
 @param src_ip - Source IP address
 @param grp_ip - Group IP address
 @param mgid_handle - Handle of multicast tree
*/
switch_status_t switch_api_multicast_mroute_tree_get(switch_device_t device,
                                        switch_handle_t vrf_handle,
                                        const switch_ip_addr_t *src_ip,
                                        const switch_ip_addr_t *grp_ip,
                                        switch_handle_t *mgid_handle);

/**
 Add an L2 (S,G) or (*, G) route entry to MFIB.
 @param device - device that programs the tree
 @param mgid_handle - Handle that uniquely identifies multicast tree
 @param vlan_handle - Handle of vlan to add L2 route
 @param src_ip - Source IP address
 @param grp_ip - Group IP address
*/
switch_status_t switch_api_multicast_l2route_add(switch_device_t device,
                                         switch_handle_t mgid_handle,
                                         switch_handle_t vlan_handle,
                                         const switch_ip_addr_t *src_ip,
                                         const switch_ip_addr_t *grp_ip);

/**
 Delete an L2 (S,G) or (*, G) route entry to MFIB.
 @param device - device that programs the tree
 @param vlan_handle - Handle of vlan to delete L2 route
 @param src_ip - Source IP address
 @param grp_ip - Group IP address
*/
switch_status_t switch_api_multicast_l2route_delete(switch_device_t device,
                                         switch_handle_t vlan_handle,
                                         const switch_ip_addr_t *src_ip,
                                         const switch_ip_addr_t *grp_ip);

/**
 For an L2 (S,G) or (*, G) get the multicast tree
 @param device - device that programs the tree
 @param vlan_handle - Handle of vlan to delete L2 route
 @param src_ip - Source IP address
 @param grp_ip - Group IP address
 @param mgid_handle - Handle of multicast tree
*/
switch_status_t switch_api_multicast_l2route_tree_get(switch_device_t device,
                                        switch_handle_t vlan_handle,
                                        const switch_ip_addr_t *src_ip,
                                        const switch_ip_addr_t *grp_ip,
                                        switch_handle_t *mgid_handle);

/** @} */ // end of mcast API

#ifdef __cplusplus
}
#endif

#endif
