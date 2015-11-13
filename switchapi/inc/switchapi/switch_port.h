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

#ifndef _switch_port_h_
#define _switch_port_h_

#include "switch_base_types.h"
#include "switch_handle.h"
#include "switch_vlan.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @defgroup Port Port configuration API
 *  API functions listed to configure the ports. Mostly
 *  related to MAC programming
    The basic configuration on the port dictates the MAC programming.
    The modes can be set to one of 1x100G, 2x50G, 4x25G, 2x40G or 4x10G.
    The ports can be configured with an administrative mode and default behavior can be set.
    The tables that get modified in response to the port APIs are mostly the early stage tables.
    The port can have a default, which generally allows tagging of untagged packets to this default
    domain for forwarding the packets through the device.
 *  @{
 */ // begin of Port

/** Port information */
typedef struct switch_api_port_info_ {
    uint16_t port_number;                           /**< FP port number */
    bool phy_detected;                              /**< whether phy is present */
    unsigned int ifg;                               /**<. inter frame gap in cycles */
    unsigned int l3mtu;                             /**< L3 MTU */
    unsigned int l2mtu;                             /**< Max frame size */
    bool learn_enable;                              /**< enable learning on port */
    bool bpdu_enable;                               /**< allow bpdu even when port is in block state */
    unsigned int egress_rate;                       /**< Max rate on egress */
    bool tunnel_term;                               /**< Permit tunnel termination */
    bool ipv4_term;                                 /**< Permit IPv4 termination */         
    bool ipv6_term;                                 /**< Permit IPv6 termination */         
    bool igmp_snoop;                                /**< Enable IGMP snopping */
    uint8_t urpf_mode;                              /**< None/Loose/Strict */
} switch_api_port_info_t;

/** port speed */
typedef enum {
    SWITCH_API_PORT_SPEED_NONE,                   /**< Port Speed Not set */
    SWITCH_API_PORT_SPEED_1G,                     /**< port speed 1G */
    SWITCH_API_PORT_SPEED_10G,                    /**< port speed 10G */
    SWITCH_API_PORT_SPEED_25G,                    /**< port speed 25G */
    SWITCH_API_PORT_SPEED_40G,                    /**< port speed 40G */
    SWITCH_API_PORT_SPEED_50G,                    /**< port speed 50G */
    SWITCH_API_PORT_SPEED_100G                    /**< port speed 100G */
} switch_port_speed_t;

/**
 * Probe for existing ports - configuration based on current status
 * or default (when called immediately after init with default
 * config
 @param device device to use
 @param max_count maximum number of ports to return
 @param count actual count returned
 @param port_info array of port_info structures per port
 */
switch_status_t switch_api_port_probe(switch_device_t device, unsigned int max_count,
                              unsigned int *count, switch_api_port_info_t *port_info);

/**
 Port Enable  Set- Enabled the port on a device
 @param device device to use
 @param port port on device to set
 @param enable TRUE => port is enabled FALSE => Port is disabled
*/
switch_status_t switch_api_port_enable_set(switch_device_t device, switch_port_t port,
                                   bool enable);

/**
 Port Enable Get - Get the Port Enabled state
 @param device device to use
 @param port port on device to get information
 @param enable TRUE => port is enabled FALSE => Port is disabled
*/
switch_status_t switch_api_port_enable_get(switch_device_t device, switch_port_t port,
                                   bool *enable);

/**
 Port Speed Set
 @param device device to use
 @param port port on device to set
 @param speed desired speed of port
*/
switch_status_t switch_api_port_speed_set(switch_device_t device, switch_port_t port,
                                  switch_port_speed_t speed);

/**
Port Speed Get
@param device device to use
@param port port on device to get
@param speed actual speed of port
*/
switch_status_t switch_api_port_speed_get(switch_device_t device, switch_port_t port,
                                  switch_port_speed_t *speed);

/**
 Port Autonegotiation Set
 @param device device to use
 @param port port on device to set
 @param enable Enable Autonegotiation if TRUE else disable
*/
switch_status_t switch_api_port_autoneg_set(switch_device_t device, switch_port_t port,
                                    bool enable);
/**
Port Autonegotiation get
@param device device to use
@param port port on device to get
@param enable returns TRUE if Autonegotiation is set else FALSE
*/
switch_status_t switch_api_port_autoneg_get(switch_device_t device, switch_port_t port,
                        bool *enable);

/** Port Pause message information */
typedef struct switch_port_pause_info_ {
    bool rx;                             /**< rx ignore PAUSE FALSE => disable PAUSE */
    bool tx;                             /**< tx send PAUSE frames when needed */
    switch_mac_addr_t mac;                   /**< MAC addr to use when sending pause frames */
    bool symmetric;                      /**< Symmetric or Asymmetric mode */
    unsigned int quanta;                 /**< time in ms after which to stop sending pause */
} switch_port_pause_info_t;

/**
 Port PAUSE control set
 @param device device to use
 @param port port on device to set
 @param pause_info Pause informaion for the port
*/
switch_status_t switch_api_port_pause_set(switch_device_t device, switch_port_t port,
                                  switch_port_pause_info_t *pause_info);

/**
 Port PAUSE control get
 @param device device to use
 @param port port on device to get
 @param pause_info Pause informaion for the port
*/
switch_status_t switch_api_port_pause_get(switch_device_t device, switch_port_t port,
                                  switch_port_pause_info_t *pause_info);

/** Priority Flow Control configuration */
typedef struct switch_pfc_config_ {
    uint32_t flags;                      /**< flags to control */
    bool lossless;                       /**< lossless mode */
    uint32_t fc_on_threshold;            /**< Threshold in bytes to turn on FC */
    uint32_t fc_off_threshold;           /**< Threshold in bytes to turn on FC */
    uint32_t drop_threshold;             /**< Discard threshold */
} switch_pfc_config_t;

/**
 Set the threshholds and mode or PFC on a port
 @param device device
 @param port port on device to configure
 @param queue on the port to configure
 @param pfc PFC configuration parameters
*/
switch_status_t switch_api_port_pfc_config_set(switch_device_t device, switch_port_t port,
                                       uint8_t queue, switch_pfc_config_t *pfc);

/**
 Port operational state
 @param device device to use
 @param port port on device to get
 @param up port state
*/
switch_status_t switch_api_port_state_get(switch_device_t device, switch_port_t port, bool *up);

/**
 Port operational state declaration interval
 @param device device to use
 @param port port on device to get
 @param interval microseconds to debounce
*/
switch_status_t switch_api_port_debounce_set(switch_device_t device, switch_port_t port,
                                     unsigned int interval);

/**
 Port set MAC in loopback
 @param device device to use
 @param port port on device to set
 @param enable loopback enabled if TRUE else FALSE
*/
switch_status_t switch_api_port_mac_loopback_set(switch_device_t device, switch_port_t port,
                                         bool enable);

/**
 Port get MAC loopback config
 @param device device to use
 @param port port on device to get
 @param enable TRUE if loopback is enabled else FALSE
*/
switch_status_t switch_api_port_mac_loopback_get(switch_device_t device, switch_port_t port,
                                         bool *enable);

/**
 Port L2 MTU settings
 @param device device to use
 @param port port on device to set
 @param l2mtu Max frame size on port
*/
switch_status_t switch_api_port_mtu_set(switch_device_t device, switch_port_t port,
                                   unsigned int l2mtu);

/**
 Port L3 MTU settings
 @param device device to use
 @param port port on device to set
 @param l3mtu IP MTU on port
*/
switch_status_t switch_api_port_l3_mtu_set(switch_device_t device, switch_port_t port,
                                   unsigned int l3mtu);

/**
 Port MTU settings get
 @param device device to use
 @param port port on device to get
 @param l2mtu maximum frame size (rx and tx)
 @param l3mtu IP MTU on port
*/
switch_status_t switch_api_port_l3_mtu_get(switch_device_t device, switch_port_t port,
                                   unsigned int *l2mtu, unsigned int *l3mtu);

/**
 Port egress rate set
 @param device device to use
 @param port port on device to set
 @param rate rate in kbps
*/
switch_status_t switch_api_port_egress_rate_set(switch_device_t device, switch_port_t port,
                        unsigned int rate);

/**
 Set Port configuration
 @param device device to use
 @param api_port_info port information inclduing port number
 (portnumber specified in port_info->port_number)
*/
switch_status_t switch_api_port_set(switch_device_t device, switch_api_port_info_t *api_port_info);

/**
 Get Port configuration
 @param device device to use
 @param api_port_info port information inclduing port number
 (portnumber specified in port_info->port_number)
*/
switch_status_t switch_api_port_get(switch_device_t device, switch_api_port_info_t *api_port_info);

/**
 Dump port table
 */
switch_status_t switch_api_port_print_all(void);

/** @} */ // end of Port

#ifdef __cplusplus
}
#endif

#endif /* defined(_switch_port_h_) */
