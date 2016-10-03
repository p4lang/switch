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

#ifndef _switch_interface_h_
#define _switch_interface_h_

#include "switch_base_types.h"
#include "switch_handle.h"
#include "switch_vlan.h"
#include "switch_l3.h"
#include "switch_tunnel.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @defgroup Interface Interface configuration API
 *  API functions listed to configure the interfaces
    Interface API
    Interfaces are the basic element for provisioning services on the device.
    Interfaces can be any of physical, link aggregation group, or tunnels.
 *  @{
 */  // begin of interface

/** Interface Types */
typedef enum switch_interface_type_ {
  SWITCH_API_INTERFACE_NONE,           /**< none */
  SWITCH_API_INTERFACE_LOOPBACK,       /**< loopback interface */
  SWITCH_API_INTERFACE_L2_VLAN_ACCESS, /**< L2 interface on VLAN */
  SWITCH_API_INTERFACE_L2_VLAN_TRUNK,  /**< L2 interface on VLAN */
  SWITCH_API_INTERFACE_L3,             /**< L3 interface on port */
  SWITCH_API_INTERFACE_L3_VLAN,        /**< L3 interface on VLAN */
  SWITCH_API_INTERFACE_L3_PORT_VLAN,   /**< Sub-Intf - L3 interface on VLAN on a
                                          port */
  SWITCH_API_INTERFACE_LAG,            /**< Interface on lag */
  SWITCH_API_INTERFACE_TUNNEL,         /**< L3 Tunnel interface  */
  SWITCH_API_INTERFACE_L2_PORT_VLAN,   /** L2 sub interface */

  SWITCH_API_INTERFACE_MAX
} switch_interface_type_t;

/** Restrict VLAN behavior on a particular port (RoCE like) */
typedef struct switch_port_vlan_ {
  switch_handle_t port_lag_handle; /**< Port or lag */
  switch_vlan_t vlan_id;           /**< VLAN id on port */
} switch_port_vlan_t;

/** Interface attributes */
typedef enum switch_intf_attr_ {
  SWITCH_INTF_ATTR_VRF,     /**< Vrf interface */
  SWITCH_INTF_ATTR_TYPE,    /**< interface attribute */
  SWITCH_INTF_ATTR_PORT_ID, /**< port id */
  SWITCH_INTF_ATTR_VLAN_ID, /**< vlan id */

  SWITCH_INTF_ATTR_RMAC_ADDR,    /**< rmac address */
  SWITCH_INTF_ATTR_V4_UNICAST,   /**< IPv4 Unicast */
  SWITCH_INTF_ATTR_V6_UNICAST,   /**< IPv6 Unicast */
  SWITCH_INTF_ATTR_V4_URPF_MODE, /**< IPv4 Urpf mode */
  SWITCH_INTF_ATTR_V6_URPF_MODE, /**< IPv6 Urpf mode */

  SWITCH_INTF_ATTR_CUSTOM_RANGE_BASE = 0x10000000, /**< Custom Attribute base */
  SWITCH_INTF_ATTR_NATIVE_VLAN,                    /**< Native Vlan */
} switch_intf_attr_t;

/** Interface information */
typedef struct switch_api_interface_info_ {
  switch_interface_type_t type; /**< type of interface */
  union {
    switch_handle_t port_lag_handle;  /**< Port or LAG handle */
    switch_vlan_t vlan_id;            /**< Vlan Inteface */
    switch_port_vlan_t port_vlan;     /**< L3 sub Interface */
    switch_tunnel_info_t tunnel_info; /**< Tunnel handle */
  } u;                                /**< Base information */

  struct {
    uint8_t core_intf : 1;     /**< interface flags */
    uint8_t flood_enabled : 1; /**< Add to flood list (only for tunnels) */
  } flags;                     /**< interface flags struct */
  // L2
  switch_handle_t native_vlan; /**< native vlan id */
  // L3
  bool ipv4_unicast_enabled;         /**< IPv4 unicast enabled */
  bool ipv6_unicast_enabled;         /**< IPv6 unicast enabled */
  bool ipv4_multicast_enabled;       /**< IPv4 multicast enabled */
  bool ipv6_multicast_enabled;       /**< IPV6 multicast menabled */
  switch_urpf_mode_t ipv4_urpf_mode; /**< IPv4 urpf mode */
  switch_urpf_mode_t ipv6_urpf_mode; /**< IPv6 urpf mode */
  unsigned char nat_mode;            /**< nat mode */
  switch_handle_t vrf_handle;        /**< vrf handle */
  bool mac_valid;                    /**< mac address valid */
  switch_mac_addr_t mac;       /**< Mac address associated with interface */
  switch_handle_t rmac_handle; /**< rmac group id */
} switch_api_interface_info_t;

/**
 Interface create
 @param device - device on which interface is created
 @param intf_info - interface information specific to type
 */
switch_handle_t switch_api_interface_create(
    switch_device_t device, switch_api_interface_info_t *intf_info);

/**
 Interface delete
 @param device - device on which interface is created
 @param interface_handle handle returned by interface creation
 */
switch_status_t switch_api_interface_delete(switch_device_t device,
                                            switch_handle_t interface_handle);

/**
 Set interface attributes
 @param intf_handle - Handle that uniquely identifies interface
 @param attr_type - Attribute of an interface
 @param value - Value that has to be set for an attribute
*/
switch_status_t switch_api_interface_attribute_set(switch_handle_t intf_handle,
                                                   switch_intf_attr_t attr_type,
                                                   uint64_t value);
/**
 Get interface attributes
 @param intf_handle - Handle that uniquely identifies interface
 @param attr_type - Attribute of an interface
 @param value - Value that has to be obtained for an attribute
*/
switch_status_t switch_api_interface_attribute_get(switch_handle_t intf_handle,
                                                   switch_intf_attr_t attr_type,
                                                   uint64_t *value);

/**
 Get the interface's port id
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Address of vrf destination
 */
switch_status_t switch_api_interface_vrf_get(switch_handle_t intf_handle,
                                             uint64_t *value);

/**
 Get the interface's port id
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Address of port id destination
 */
switch_status_t switch_api_interface_port_id_get(switch_handle_t intf_handle,
                                                 uint64_t *value);

/**
 Get the interface's vlan id
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Address of vlan id destination
 */
switch_status_t switch_api_interface_vlan_id_get(switch_handle_t intf_handle,
                                                 uint64_t *value);

/**
 Get the interface's mac address
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Address of destination mac container
 */
switch_status_t switch_api_interface_rmac_addr_get(switch_handle_t intf_handle,
                                                   uint64_t *value);

/**
 Set IPv4 enable interface attribute
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Enable/Disable V4 routing on interface
*/
switch_status_t switch_api_interface_ipv4_unicast_enabled_set(
    switch_handle_t intf_handle, uint64_t value);

/**
 Get IPv4 enable interface attribute
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Get V4 routing on interface
*/
switch_status_t switch_api_interface_ipv4_unicast_enabled_get(
    switch_handle_t intf_handle, uint64_t *value);

/**
 Set IPv6 enable interface attribute
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Enable/Disable V4 routing on interface
*/
switch_status_t switch_api_interface_ipv6_unicast_enabled_set(
    switch_handle_t intf_handle, uint64_t value);

/**
 Get IPv6 enable interface attribute
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Get V4 routing on interface
*/
switch_status_t switch_api_interface_ipv6_unicast_enabled_get(
    switch_handle_t intf_handle, uint64_t *value);

/**
 Set IPv4 multicast enable interface attribute
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Enable/Disable V4 multicast routing on interface
*/
switch_status_t switch_api_interface_ipv4_multicast_enabled_set(
    switch_handle_t intf_handle, uint64_t value);

/**
 Get IPv4 multicast enable interface attribute
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Get V4 multicast routing on interface
*/
switch_status_t switch_api_interface_ipv4_multicast_enabled_get(
    switch_handle_t intf_handle, uint64_t *value);

/**
 Set IPv6 multicast enable interface attribute
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Enable/Disable V4 multicast routing on interface
*/
switch_status_t switch_api_interface_ipv6_multicast_enabled_set(
    switch_handle_t intf_handle, uint64_t value);

/**
 Get IPv6 multicast enable interface attribute
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Get V4 multicast routing on interface
*/
switch_status_t switch_api_interface_ipv6_multicast_enabled_get(
    switch_handle_t intf_handle, uint64_t *value);

/**
 Set IPv4 unicast rpf mode interface attribute
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Unicast RPF mode
*/
switch_status_t switch_api_interface_ipv4_urpf_mode_set(
    switch_handle_t intf_handle, uint64_t value);

/**
 Get IPv4 unicast rpf mode interface attribute
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Unicast RPF mode
*/
switch_status_t switch_api_interface_ipv4_urpf_mode_get(
    switch_handle_t intf_handle, uint64_t *value);

/**
 Set IPv6 unicast rpf mode interface attribute
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Unicast RPF mode
*/
switch_status_t switch_api_interface_ipv6_urpf_mode_set(
    switch_handle_t intf_handle, uint64_t value);

/**
 Get IPv6 unicast rpf mode interface attribute
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Unicast RPF mode
*/
switch_status_t switch_api_interface_ipv6_urpf_mode_get(
    switch_handle_t intf_handle, uint64_t *value);

/**
 Set NAT mode interface attribute
 @param intf_handle - Handle that uniquely identifies interface
 @param value - NAT mode
*/
switch_status_t switch_api_interface_nat_mode_set(switch_handle_t intf_handle,
                                                  uint8_t value);

/**
 Get NAT mode interface attribute
 @param intf_handle - Handle that uniquely identifies interface
 @param value - NAT mode
*/
switch_status_t switch_api_interface_nat_mode_get(switch_handle_t intf_handle,
                                                  uint8_t *value);

/**
 Set native vlan on interface
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Value of native vlan
*/
switch_status_t switch_api_interface_native_vlan_set(
    switch_handle_t intf_handle, uint64_t value);

/**
 Get native vlan on interface
 @param intf_handle - Handle that uniquely identifies interface
 @param value - Value of native vlan
*/
switch_status_t switch_api_interface_native_vlan_get(
    switch_handle_t intf_handle, uint64_t *value);

/**
 Iterator function prototype for l3 interfaces
 @param intf_info Interface Info
 */
typedef switch_status_t (*switch_l3_interfaces_iterator_fn)(
    switch_api_interface_info_t intf_info);

/**
 Get all l3 interfaces
 @param iterator_fn Iterator function to be called for every l3 interface
 */
switch_status_t switch_api_interface_l3_ifs_get(
    switch_l3_interfaces_iterator_fn iterator_fn);

/**
 Given an interface handle, get the associated port handle
 @param intf_handle - Handle that uniquely identifies interface
 @param port_handle - Port handle associated with the interface
 */
switch_status_t switch_api_interface_get_port_handle(
    switch_handle_t intf_handle, switch_handle_t *port_handle);

/**
 Given an L3 interface handle, get the associated vlan handle
 @param intf_handle - Handle that uniquely identifies interface
 @param vlan_handle - Vlan handle associated with the interface
 */
switch_status_t switch_api_interface_get_vlan_handle(
    switch_handle_t intf_handle, switch_handle_t *vlan_handle);

/**
 Given an interface handle, get its type
 @param intf_handle - Handle that uniquely identifies interface
 @param type - Interface type
 */
switch_status_t switch_api_interface_get_type(switch_handle_t intf_handle,
                                              switch_interface_type_t *type);

/**
 enable bd stats on interface
 @param device device
 @param intf_handle - Handle that uniquely identifies interface
 */
switch_status_t switch_api_l3_interface_bd_stats_enable(
    switch_device_t device, switch_handle_t intf_handle);

/**
 disable bd stats on interface
 @param device device
 @param intf_handle - Handle that uniquely identifies interface
 */
switch_status_t switch_api_l3_interface_bd_stats_disable(
    switch_device_t device, switch_handle_t intf_handle);

/**
 get stats on l3 interface
 @param device device
 @param intf_handle - Handle that uniquely identifies interface
 @param count number of counters
 @param counter_ids counter ids
 @param counters counter return value
 */
switch_status_t switch_api_l3_interface_stats_get(
    switch_device_t device,
    switch_handle_t intf_handle,
    uint8_t count,
    switch_bd_stats_id_t *counter_ids,
    switch_counter_t *counters);

/**
 Dump interface table
 */
switch_status_t switch_api_interface_print_all(void);

/** @} */  // end of interface

#ifdef __cplusplus
}
#endif

#endif
