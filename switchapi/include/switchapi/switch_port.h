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
#include "switch_meter.h"

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
 */  // begin of Port

/** Maximum number of port priority groups */
#define SWITCH_MAX_PPG 32

/** Port information */
typedef struct switch_api_port_info_ {
  uint16_t port_number;     /**< FP port number */
  bool phy_detected;        /**< whether phy is present */
  unsigned int ifg;         /**<. inter frame gap in cycles */
  unsigned int l3mtu;       /**< L3 MTU */
  unsigned int l2mtu;       /**< Max frame size */
  bool learn_enable;        /**< enable learning on port */
  bool bpdu_enable;         /**< allow bpdu even when port is in block state */
  unsigned int egress_rate; /**< Max rate on egress */
  bool tunnel_term;         /**< Permit tunnel termination */
  bool ipv4_term;           /**< Permit IPv4 termination */
  bool ipv6_term;           /**< Permit IPv6 termination */
  bool igmp_snoop;          /**< Enable IGMP snopping */
  uint8_t urpf_mode;        /**< None/Loose/Strict */
} switch_api_port_info_t;

/** port speed */
typedef enum {
  SWITCH_API_PORT_SPEED_NONE, /**< Port Speed Not set */
  SWITCH_API_PORT_SPEED_1G,   /**< port speed 1G */
  SWITCH_API_PORT_SPEED_10G,  /**< port speed 10G */
  SWITCH_API_PORT_SPEED_25G,  /**< port speed 25G */
  SWITCH_API_PORT_SPEED_40G,  /**< port speed 40G */
  SWITCH_API_PORT_SPEED_50G,  /**< port speed 50G */
  SWITCH_API_PORT_SPEED_100G  /**< port speed 100G */
} switch_port_speed_t;

/** port flowcontrol type */
typedef enum switch_flowcontrol_type_ {
  SWITCH_FLOWCONTROL_TYPE_NONE = 0,
  SWITCH_FLOWCONTROL_TYPE_PFC = 1,
  SWITCH_FLOWCONTROL_TYPE_PAUSE = 2
} switch_flowcontrol_type_t;

/**
 * Probe for existing ports - configuration based on current status
 * or default (when called immediately after init with default
 * config
 @param device device to use
 @param max_count maximum number of ports to return
 @param count actual count returned
 @param port_info array of port_info structures per port
 */
switch_status_t switch_api_port_probe(switch_device_t device,
                                      unsigned int max_count,
                                      unsigned int *count,
                                      switch_api_port_info_t *port_info);

/**
 Port Enable  Set- Enabled the port on a device
 @param device device to use
 @param port port on device to set
 @param enable TRUE => port is enabled FALSE => Port is disabled
*/
switch_status_t switch_api_port_enable_set(switch_device_t device,
                                           switch_port_t port,
                                           bool enable);

/**
 Port Enable Get - Get the Port Enabled state
 @param device device to use
 @param port port on device to get information
 @param enable TRUE => port is enabled FALSE => Port is disabled
*/
switch_status_t switch_api_port_enable_get(switch_device_t device,
                                           switch_port_t port,
                                           bool *enable);

/**
 Port Speed Set
 @param device device to use
 @param port port on device to set
 @param speed desired speed of port
*/
switch_status_t switch_api_port_speed_set(switch_device_t device,
                                          switch_port_t port,
                                          switch_port_speed_t speed);

/**
Port Speed Get
@param device device to use
@param port port on device to get
@param speed actual speed of port
*/
switch_status_t switch_api_port_speed_get(switch_device_t device,
                                          switch_port_t port,
                                          switch_port_speed_t *speed);

/**
 Port Autonegotiation Set
 @param device device to use
 @param port port on device to set
 @param enable Enable Autonegotiation if TRUE else disable
*/
switch_status_t switch_api_port_autoneg_set(switch_device_t device,
                                            switch_port_t port,
                                            bool enable);
/**
Port Autonegotiation get
@param device device to use
@param port port on device to get
@param enable returns TRUE if Autonegotiation is set else FALSE
*/
switch_status_t switch_api_port_autoneg_get(switch_device_t device,
                                            switch_port_t port,
                                            bool *enable);

/** Port Pause message information */
typedef struct switch_port_pause_info_ {
  bool rx;               /**< rx ignore PAUSE FALSE => disable PAUSE */
  bool tx;               /**< tx send PAUSE frames when needed */
  switch_mac_addr_t mac; /**< MAC addr to use when sending pause frames */
  bool symmetric;        /**< Symmetric or Asymmetric mode */
  unsigned int quanta;   /**< time in ms after which to stop sending pause */
} switch_port_pause_info_t;

/**
 Port operational state
 @param device device to use
 @param port port on device to get
 @param up port state
*/
switch_status_t switch_api_port_state_get(switch_device_t device,
                                          switch_port_t port,
                                          bool *up);

/**
 Port operational state declaration interval
 @param device device to use
 @param port port on device to get
 @param interval microseconds to debounce
*/
switch_status_t switch_api_port_debounce_set(switch_device_t device,
                                             switch_port_t port,
                                             unsigned int interval);

/**
 Port set MAC in loopback
 @param device device to use
 @param port port on device to set
 @param enable loopback enabled if TRUE else FALSE
*/
switch_status_t switch_api_port_mac_loopback_set(switch_device_t device,
                                                 switch_port_t port,
                                                 bool enable);

/**
 Port get MAC loopback config
 @param device device to use
 @param port port on device to get
 @param enable TRUE if loopback is enabled else FALSE
*/
switch_status_t switch_api_port_mac_loopback_get(switch_device_t device,
                                                 switch_port_t port,
                                                 bool *enable);

/**
 Port L2 MTU settings
 @param device device to use
 @param port port on device to set
 @param l2mtu Max frame size on port
*/
switch_status_t switch_api_port_mtu_set(switch_device_t device,
                                        switch_port_t port,
                                        unsigned int l2mtu);

/**
 Port L3 MTU settings
 @param device device to use
 @param port port on device to set
 @param l3mtu IP MTU on port
*/
switch_status_t switch_api_port_l3_mtu_set(switch_device_t device,
                                           switch_port_t port,
                                           unsigned int l3mtu);

/**
 Port MTU settings get
 @param device device to use
 @param port port on device to get
 @param l2mtu maximum frame size (rx and tx)
 @param l3mtu IP MTU on port
*/
switch_status_t switch_api_port_l3_mtu_get(switch_device_t device,
                                           switch_port_t port,
                                           unsigned int *l2mtu,
                                           unsigned int *l3mtu);

/**
 Port egress rate set
 @param device device to use
 @param port port on device to set
 @param rate rate in kbps
*/
switch_status_t switch_api_port_egress_rate_set(switch_device_t device,
                                                switch_port_t port,
                                                unsigned int rate);

/**
 Set Port configuration
 @param device device to use
 @param api_port_info port information inclduing port number
 (portnumber specified in port_info->port_number)
*/
switch_status_t switch_api_port_set(switch_device_t device,
                                    switch_api_port_info_t *api_port_info);

/**
 Get Port configuration
 @param device device to use
 @param api_port_info port information inclduing port number
 (portnumber specified in port_info->port_number)
*/
switch_status_t switch_api_port_get(switch_device_t device,
                                    switch_api_port_info_t *api_port_info);

/**
 Set meter handle for port
 @param device device to use
 @param port port on device
 @param pkt_type packet type
 @param meter_handle meter handle
 */
switch_status_t switch_api_port_storm_control_set(switch_device_t device,
                                                  switch_port_t port,
                                                  switch_packet_type_t pkt_type,
                                                  switch_handle_t meter_handle);

/**
 Get meter handle for port
 @param device device to use
 @param port port on device
 @param pkt_type packet type
 @param meter_handle meter handle
 */
switch_status_t switch_api_port_storm_control_get(
    switch_device_t device,
    switch_port_t port,
    switch_packet_type_t pkt_type,
    switch_handle_t *meter_handle);
/**
 Meter stats
 @param device device
 @param meter_handle meter handle
 @param count number of counters
 @param counter_ids meter counter ids
 @param counters counter values
 */
switch_status_t switch_api_storm_control_stats_get(
    switch_device_t device,
    switch_handle_t meter_handle,
    uint8_t count,
    switch_meter_stats_t *counter_ids,
    switch_counter_t *counters);

/**
 Get port priority groups
 @param device device
 @param port_handle port handle
 @param num_ppgs number of ppgs
 @param ppg_handles list of ppg handles
*/
switch_status_t switch_api_ppg_get(switch_device_t device,
                                   switch_handle_t port_handle,
                                   uint8_t *num_ppgs,
                                   switch_handle_t *ppg_handles);

/**
 port drop limit set
 @param device device
 @param port_handle port handle
 @param num_bytes number of bytes
*/
switch_status_t switch_api_port_drop_limit_set(switch_device_t device,
                                               switch_handle_t port_handle,
                                               uint32_t num_bytes);

/**
 port drop hysteresis set
 @param device device
 @param port_handle port handle
 @param num_bytes number of bytes
*/
switch_status_t switch_api_port_drop_hysteresis_set(switch_device_t device,
                                                    switch_handle_t port_handle,
                                                    uint32_t num_bytes);

/**
 Set port to cos mapping in ingress
 @param device device
 @param port_handle port handle
 @param ppg_handle priority group handle
 @param cos_bitmap cos bitmap
*/
switch_status_t switch_api_port_cos_mapping(switch_device_t device,
                                            switch_handle_t port_handle,
                                            switch_handle_t ppg_handle,
                                            uint8_t cos_bitmap);

/**
 Set port cos and pfc cos mapping
 @param device device
 @param port_handle port handle
 @param cos_to_icos cos to ingress cos bitmap
*/
switch_status_t switch_api_port_pfc_cos_mapping(switch_device_t device,
                                                switch_handle_t port_handle,
                                                uint8_t *cos_to_icos);

/**
 Enable port shaping
 @param device device
 @param port_handle port handle
 @param shaper_type shaper type in bytes or packets
 @param burst_size burst size
 @param rate rate
*/
switch_status_t switch_api_port_shaping_enable(switch_device_t device,
                                               switch_handle_t port_handle,
                                               switch_shaper_type_t shaper_type,
                                               uint32_t burst_size,
                                               uint32_t rate);

/**
 Disable port shaping
 @param device device
 @param port_handle port handle
*/
switch_status_t switch_api_port_shaping_disable(switch_device_t device,
                                                switch_handle_t port_handle);

/**
 enable dscp trust on port
 @param device device
 @param port_handle port handle
 @param trust_dscp dscp trust
*/
switch_status_t switch_api_port_trust_dscp_set(switch_device_t device,
                                               switch_handle_t port_handle,
                                               bool trust_dscp);

/**
 enable pcp trust on port
 @param device device
 @param port_handle port handle
 @param trust_pcp pcp trust
*/
switch_status_t switch_api_port_trust_pcp_set(switch_device_t device,
                                              switch_handle_t port_handle,
                                              bool trust_pcp);

/**
 enable lossless mode in port priority group
 @param device device
 @param ppg_handle ppg handle
 @param enable enable
*/
switch_status_t switch_api_ppg_lossless_enable(switch_device_t device,
                                               switch_handle_t ppg_handle,
                                               bool enable);

/**
 set guaranteed limit on ppg
 @param device device
 @param ppg_handle ppg handle
 @param num_bytes number of bytes
*/
switch_status_t switch_api_ppg_guaranteed_limit_set(switch_device_t device,
                                                    switch_handle_t ppg_handle,
                                                    uint32_t num_bytes);

/**
 set skid lmit on ppg
 @param device device
 @param ppg_handle ppg handle
 @param num_bytes number of bytes
*/
switch_status_t switch_api_ppg_skid_limit_set(switch_device_t device,
                                              switch_handle_t ppg_handle,
                                              uint32_t num_bytes);

/**
 set hystersis lmit on ppg
 @param device device
 @param ppg_handle ppg handle
 @param num_bytes number of bytes
*/
switch_status_t switch_api_ppg_skid_hysteresis_set(switch_device_t device,
                                                   switch_handle_t ppg_handle,
                                                   uint32_t num_bytes);

/**
 set ingress qos group on port
 @param device device
 @param port_handle port handle
 @param qos_group qos group
*/
switch_status_t switch_api_port_qos_group_ingress_set(
    switch_device_t device,
    switch_handle_t port_handle,
    switch_handle_t qos_group);

/**
 set tc qos group on port
 @param device device
 @param port_handle port handle
 @param qos_group qos group
*/
switch_status_t switch_api_port_qos_group_tc_set(switch_device_t device,
                                                 switch_handle_t port_handle,
                                                 switch_handle_t qos_group);

/**
 set egress qos group on port
 @param device device
 @param port_handle port handle
 @param qos_group qos group
*/
switch_status_t switch_api_port_qos_group_egress_set(
    switch_device_t device,
    switch_handle_t port_handle,
    switch_handle_t qos_group);

/**
 set default tc on port
 @param device device
 @param port_handle port handle
 @param tc traffic class
*/
switch_status_t switch_api_port_tc_default_set(switch_device_t device,
                                               switch_handle_t port_handle,
                                               uint16_t tc);

/**
 set default color on port
 @param device device
 @param port_handle port handle
 @param color packet color
*/
switch_status_t switch_api_port_color_default_set(switch_device_t device,
                                                  switch_handle_t port_handle,
                                                  switch_color_t color);

/**
 set port flowcontrol mode
 @param device device
 @param port_handle port handle
 @param flow_control flow control type
*/
switch_status_t switch_api_port_flowcontrol_mode_set(
    switch_device_t device,
    switch_handle_t port_handle,
    switch_flowcontrol_type_t flow_control);
/**
 Dump port table
 */
switch_status_t switch_api_port_print_all(void);

/** @} */  // end of Port

#ifdef __cplusplus
}
#endif

#endif /* defined(_switch_port_h_) */
