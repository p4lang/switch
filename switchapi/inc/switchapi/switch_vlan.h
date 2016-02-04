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

#ifndef _switch_vlan_h_
#define _switch_vlan_h_

#include "switch_base_types.h"
#include "switch_handle.h"
#include "switch_status.h"
#include "switch_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SWITCH_API_MAX_VLANS 4096

/** Logical Network Type */
typedef enum {
    SWITCH_LOGICAL_NETWORK_TYPE_NONE,               /**< Unitialized domain type */
    SWITCH_LOGICAL_NETWORK_TYPE_VLAN,               /**< VLAN domain */
    SWITCH_LOGICAL_NETWORK_TYPE_GRE,                /**< GRE Network */
    SWITCH_LOGICAL_NETWORK_TYPE_L3,                 /**< L3 Network */
    SWITCH_LOGICAL_NETWORK_TYPE_ENCAP_BASIC,        /**< Encap from logical network */
    SWITCH_LOGICAL_NETWORK_TYPE_ENCAP_ENHANCED      /**< Encap from interface */
} switch_logical_network_type_t;

typedef enum {
    SWITCH_VLAN_FLOOD_NONE = 0x0,
    SWITCH_VLAN_FLOOD_UUC = 0x1,
    SWITCH_VLAN_FLOOD_UMC = 0x2,
    SWITCH_VLAN_FLOOD_BCAST = 0x4
} switch_vlan_flood_type_t;

typedef enum switch_vlan_tagging_mode_
{
    SWITCH_VLAN_PORT_UNTAGGED,
    SWITCH_VLAN_PORT_TAGGED,
    SWITCH_VLAN_PORT_PRIORITY_TAGGED
} switch_vlan_tagging_mode_t;

typedef enum switch_vlan_attr_
{
    /* Maximum number of learned MAC addresses [uint32_t] */
    SWITCH_VLAN_ATTR_MAX_LEARNED_ADDRESSES,

    /* Custom range base value */
    SWITCH_VLAN_ATTR_CUSTOM_RANGE_BASE  = 0x10000000,
    SWITCH_VLAN_ATTR_FLOOD_TYPE,
    SWITCH_VLAN_ATTR_VRF_ID,
    SWITCH_VLAN_ATTR_AGE_INTERVAL,
    SWITCH_VLAN_ATTR_IGMP_SNOOPING,
    SWITCH_VLAN_ATTR_MLD_SNOOPING,
    SWITCH_VLAN_ATTR_MAC_LEARNING
} switch_vlan_attr_t;

typedef enum switch_ln_attr_
{
    /* Maximum number of learned MAC addresses [uint32_t] */
    SWITCH_LN_ATTR_MAX_LEARNED_ADDRESSES,

    /* Custom range base value */
    SWITCH_LN_ATTR_CUSTOM_RANGE_BASE  = 0x10000000,
    SWITCH_LN_ATTR_FLOOD_TYPE,
    SWITCH_LN_ATTR_VRF_ID,
    SWITCH_LN_ATTR_NETWORK_TYPE,
    SWITCH_LN_ATTR_AGE_INTERVAL,
    SWITCH_LN_ATTR_IPV4_UNICAST,
    SWITCH_LN_ATTR_IPV6_UNICAST,
    SWITCH_LN_ATTR_IGMP_SNOOPING,
    SWITCH_LN_ATTR_MLD_SNOOPING,
    SWITCH_LN_ATTR_IPV4_MCAST_MODE,
    SWITCH_LN_ATTR_IPV6_MCAST_MODE,
    SWITCH_LN_ATTR_MAC_LEARNING
} switch_ln_attr_t;

typedef enum _switch_vlan_stats_t
{
    SWITCH_VLAN_STATS_IN_UCAST,
    SWITCH_VLAN_STATS_IN_MCAST,
    SWITCH_VLAN_STATS_IN_BCAST,
    SWITCH_VLAN_STATS_IN_DROP,
    SWITCH_VLAN_STATS_OUT_UCAST,
    SWITCH_VLAN_STATS_OUT_MCAST,
    SWITCH_VLAN_STATS_OUT_BCAST,
    SWITCH_VLAN_STATS_OUT_DROP,
    SWITCH_VLAN_STATS_MAX,
} switch_vlan_stats_t;

/** vlan port info */
typedef struct switch_vlan_port_ {
    switch_handle_t handle;                    /**< port or interface handle */
    switch_vlan_tagging_mode_t tagging_mode;   /**< tagging mode */
} switch_vlan_port_t;

typedef struct switch_vlan_interface_ {
    switch_handle_t vlan_handle;
    switch_handle_t intf_handle;
} switch_vlan_interface_t;

/** Logical Network information */
typedef struct switch_logical_network_ {
    switch_logical_network_type_t type;       /**< Type of logical network */
    switch_handle_t vrf_handle;               /**< VRF of domain */
    switch_handle_t rmac_handle;              /**< RMAC Group */
    switch_encap_info_t encap_info;           /**< Logical network encap */

    struct {
        uint8_t ipv4_unicast_enabled:1;       /**< v4 unicast enabled */
        uint8_t ipv6_unicast_enabled:1;       /**< v6 unicast enabled */
        uint8_t ipv4_multicast_enabled:1;     /**< v4 multicast enabled */
        uint8_t ipv6_multicast_enabled:1;     /**< v6 multicast enabled */
        uint8_t igmp_snooping_enabled:1;      /**< igmp snooping enabled */
        uint8_t mld_snooping_enabled:1;       /**< mld snooping enabled */
        uint8_t flood_enabled:1;              /**< default flood */
        uint8_t learn_enabled:1;              /**< learn enabled */
        uint8_t core_bd:1;                    /**< code or edge vlan */
        uint8_t stats_enabled:1;
    } flags;                                  /**< vlan flags */

    switch_vlan_flood_type_t flood_type;      /**< flood type */
    unsigned int age_interval;                /**< age interval for VLAN */
    unsigned int member_count;                /**< Count of members */

    uint16_t bd_label;                        /**< acl label for vlan */
    uint8_t mrpf_group;                       /**< multicast rpf group */
} switch_logical_network_t;

/** @defgroup VLAN VLAN configuration API
 *  API functions listed to configure VLAN
    The basic L2 domain for isolating traffic is configured using
    configuration of VLANs.  The maximum number of VLANs supported
    on the device is limited to 4k (4096). The operations on VLAN
    correspond to setting up broadcast domain and optionally ingress
    and egress VLAN translate tables.
 *  @{
 */ // begin of VLAN

// VLAN

/**
 VLAN create
 @param device device
 @param vlan_id Id of the VLAN
*/
switch_handle_t switch_api_vlan_create(switch_device_t device, switch_vlan_t vlan_id);

/**
 Delete VLAN
 @param device device
 @param vlan_handle handle of VLAN returned by create
*/

switch_status_t switch_api_vlan_delete(switch_device_t device, switch_handle_t vlan_handle);

/**
  Set a value for an attribute. There is a list of attributes
  that can be set based on SAI.
  @param vlan_handle - Vlan handle that identifies vlan uniquely
  @param attr_type - Attribute that has to be set for vlan
  @param value - Value of the attribute
*/
switch_status_t switch_api_vlan_attribute_set(switch_handle_t vlan_handle,
                                      switch_vlan_attr_t attr_type,
                                      uint64_t value);

/**
  Get a value for an attribute. There is a list of attributes
  that can be obtained based on SAI.
  @param vlan_handle - Vlan handle that identifies vlan uniquely
  @param attr_type - Attribute that has to be obtained from vlan
  @param value - Value of the attribute
*/
switch_status_t switch_api_vlan_attribute_get(switch_handle_t vlan_handle,
                                      switch_vlan_attr_t attr_type,
                                      uint64_t *value);
/**
  Set the flood type for vlan. Based on the flood type, flood lists
  are allocated. By default, none of the flood lists are created.
  @param vlan_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of flood type
*/
switch_status_t switch_api_vlan_flood_type_set(switch_handle_t vlan_handle, uint64_t value);

/**
  Get the flood type for vlan. Based on the flood type, flood lists
  are allocated. By default, none of the flood lists are created.
  @param vlan_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of flood type
*/
switch_status_t switch_api_vlan_flood_type_get(switch_handle_t vlan_handle, uint64_t *value);

/**
  Set the vrf handle for vlan.
  @param vlan_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of vrf handle
*/
switch_status_t switch_api_vlan_vrf_handle_set(switch_handle_t vlan_handle, uint64_t value);

/**
  Get the vrf handle for vlan.
  @param vlan_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of vrf handle
*/
switch_status_t switch_api_vlan_vrf_handle_get(switch_handle_t vlan_handle, uint64_t *value);

/**
  Set the logical network type of a vlan
  @param ln_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of logical network type
*/
switch_status_t switch_api_ln_network_type_set(switch_handle_t ln_handle, uint64_t value);

/**
  Get the logical network type of a vlan
  @param ln_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of logical network type
*/
switch_status_t switch_api_ln_network_type_get(switch_handle_t ln_handle, uint64_t *value);

/**
  Set IPv4 unicast routing enabled for vlan
  @param ln_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of IPv4 unicast routing enabled
*/
switch_status_t switch_api_ln_ipv4_unicast_enabled_set(switch_handle_t ln_handle, uint64_t value);

/**
  Get IPv4 unicast routing enabled for vlan
  @param ln_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of IPv4 unicast routing enabled
*/
switch_status_t switch_api_ln_ipv4_unicast_enabled_get(switch_handle_t ln_handle, uint64_t *value);

/**
  Set IPv6 unicast routing enabled for vlan
  @param ln_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of IPv6 unicast routing enabled
*/
switch_status_t switch_api_ln_ipv6_unicast_enabled_set(switch_handle_t ln_handle, uint64_t value);

/**
  Get IPv6 unicast routing enabled for vlan
  @param ln_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of IPv6 unicast routing enabled
*/
switch_status_t switch_api_ln_ipv6_unicast_enabled_get(switch_handle_t ln_handle, uint64_t *value);

/**
  Set IPv4 multicast routing enabled for vlan
  @param ln_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of IPv4 multicast routing enabled
*/
switch_status_t switch_api_ln_ipv4_multicast_enabled_set(switch_handle_t ln_handle, uint64_t value);

/**
  Get IPv4 multicast routing enabled for vlan
  @param ln_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of IPv4 multicast routing enabled
*/
switch_status_t switch_api_ln_ipv4_multicast_enabled_get(switch_handle_t ln_handle, uint64_t *value);

/**
  Set IPv6 multicast routing enabled for vlan
  @param ln_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of IPv6 multicast routing enabled
*/
switch_status_t switch_api_ln_ipv6_multicast_enabled_set(switch_handle_t ln_handle, uint64_t value);

/**
  Get IPv6 multicast routing enabled for vlan
  @param ln_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of IPv6 multicast routing enabled
*/
switch_status_t switch_api_ln_ipv6_multicast_enabled_get(switch_handle_t ln_handle, uint64_t *value);

/**
  Set mac learning enabled for vlan
  @param vlan_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of mac learning enabled
*/
switch_status_t switch_api_vlan_learning_enabled_set(switch_handle_t vlan_handle, uint64_t value);

/**
  Get mac learning enabled on vlan
  @param vlan_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of mac learning enabled
*/
switch_status_t switch_api_vlan_learning_enabled_get(switch_handle_t vlan_handle, uint64_t *value);

/**
  Set mac age interval on vlan
  @param vlan_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of mac learning enabled
*/
switch_status_t switch_api_vlan_aging_interval_set(switch_handle_t vlan_handle, uint64_t value);

/**
  Get mac age interval on vlan
  @param vlan_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of mac age interval
*/
switch_status_t switch_api_vlan_aging_interval_get(switch_handle_t vlan_handle, uint64_t *value);

/**
  Set igmp snooping enable flag for vlan
  @param vlan_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of igmp snooping enabled flag
*/
switch_status_t switch_api_vlan_igmp_snooping_enabled_set(switch_handle_t vlan_handle, uint64_t value);

/**
  Get igmp snooping enable flag for vlan
  @param vlan_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of igmp snooping enabled flag
*/
switch_status_t switch_api_vlan_igmp_snooping_enabled_get(switch_handle_t vlan_handle, uint64_t *value);

/**
  Set mld snooping enable flag for vlan
  @param vlan_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of mld snooping enabled flag
*/
switch_status_t switch_api_vlan_mld_snooping_enabled_set(switch_handle_t vlan_handle, uint64_t value);

/**
  Get mld snooping enable flag for vlan
  @param vlan_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of mld snooping enabled flag
*/
switch_status_t switch_api_vlan_mld_snooping_enabled_get(switch_handle_t vlan_handle, uint64_t *value);

/**
  Set mrpf group for vlan
  @param vlan_handle - Vlan handle that identifies vlan uniquely
  @param value - Value of mrpf group
*/
switch_status_t switch_api_vlan_mrpf_group_set(switch_handle_t vlan_handle, uint64_t value);

/**
  Add ports to vlan. By default, ports will be added to the flood list
  based on the flood type.
  @param device device
  @param vlan_handle - Vlan handle that identifies vlan uniquely
  @param port_count - Number of ports to be added to vlan
  @param vlan_port - List of interfaces/ports/lags
*/
switch_status_t switch_api_vlan_ports_add(switch_device_t device, switch_handle_t vlan_handle,
                                          uint16_t port_count, switch_vlan_port_t *vlan_port);

/**
  Remove ports from vlan. By default, ports will be removed from flood list
  based on the flood type.
  @param device device
  @param vlan_handle - Vlan handle that identifies vlan uniquely
  @param port_count - Number of ports to be removed from vlan
  @param vlan_port- List of interfaces/ports/lags
*/
switch_status_t switch_api_vlan_ports_remove(switch_device_t device, switch_handle_t vlan_handle,
                                             uint16_t port_count, switch_vlan_port_t  *vlan_port);

/**
  Get the list of interfaces that belong to a vlan.
  @param device device
  @param vlan_handle - Vlan handle that identifies vlan uniquely
  @param mbr_count - Number of interfaces
  @param mbrs - List of interfaces
*/
switch_status_t switch_api_vlan_interfaces_get(switch_device_t device,
                                          switch_handle_t vlan_handle,
                                          uint16_t *mbr_count,
                                          switch_vlan_interface_t **mbrs);

/**
 Create a Logical network
 @param device -  device to be programmed
 @param ln_info - Logical network information
*/
switch_handle_t switch_api_logical_network_create(switch_device_t device,
                                          switch_logical_network_t *ln_info);

/**
 Update a Logical network
 @param device -  device to be programmed
 @param network_handle handle of logical network
 @param ln_info - Logical network information
*/
switch_status_t switch_api_logical_network_update(switch_device_t device,
                                          switch_handle_t network_handle,
                                          switch_logical_network_t *ln_info);

/**
 Delete a Logical network
 @param device -  device to be programmed
 @param network_handle handle of logical network
*/
switch_status_t switch_api_logical_network_delete(switch_device_t device, switch_handle_t network_handle);

/**
 Set vlan id to vlan handle mapping
 @param vlan_id vlan id
 @param vlan_handle vlan handle
*/
switch_status_t switch_api_vlan_id_to_handle_set(switch_vlan_t vlan_id,
                                                 switch_handle_t vlan_handle);

/**
 Get vlan id to vlan handle mapping
 @param vlan_id vlan id
 @param vlan_handle vlan handle
*/
switch_status_t switch_api_vlan_id_to_handle_get(switch_vlan_t vlan_id,
                                                 switch_handle_t *vlan_handle);

/**
 Get vlan handle to vlan id mapping
 @param vlan_handle vlan handle
 @param vlan_id vlan id
*/
switch_status_t switch_api_vlan_handle_to_id_get(switch_handle_t vlan_handle,
                                                 switch_vlan_t *vlan_id);
/**
 Dump vlan table
 */
switch_status_t switch_api_vlan_print_all(void);

/**
 Enable vlan statistics
 @param device device to be programmed
 @param vlan_handle Vlan handle that identifies vlan uniquely
 */
switch_status_t switch_api_vlan_stats_enable(switch_device_t device, switch_handle_t vlan_handle);

/**
 Enable vlan statistics
 @param device device to be programmed
 @param vlan_handle Vlan handle that identifies vlan uniquely
 */
switch_status_t switch_api_vlan_stats_disable(switch_device_t device, switch_handle_t vlan_handle);

/**
 Get vlan statistics
 @param vlan_handle Vlan handle that identifies vlan uniquely
 @param count number of counter ids
 @param counter_ids list of counter ids
 @param counters counter values to be returned
 */
switch_status_t switch_api_vlan_stats_get(
        switch_device_t device,
        switch_handle_t vlan_handle,
        uint8_t count,
        switch_vlan_stats_t *counter_ids,
        switch_counter_t *counters);

/** @} */ // end of VLAN

#ifdef __cplusplus
}
#endif

#endif
