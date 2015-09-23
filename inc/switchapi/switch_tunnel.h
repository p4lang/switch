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

#ifndef _switch_tunnel_h_
#define _switch_tunnel_h_

#include "switch_handle.h"
#include "switch_vlan.h"
#include "switch_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @defgroup Tunnel Tunnel API
 *  API functions create tunnel interfaces
 *  @{
 */ // begin of Tunnel API

/** Tunnel encap mode */
typedef enum switch_encap_mode_ {
    SWITCH_API_TUNNEL_ENCAP_MODE_IP,
    SWITCH_API_TUNNEL_ENCAP_MODE_MPLS
} switch_encap_mode_t;

/** Tunnel information */
typedef struct switch_tunnel_info_ {
    switch_encap_info_t encap_info;              /**< Encap Info */
    switch_encap_mode_t encap_mode;              /**< Encap mode - ip/mpls */
    union {
        switch_ip_encap_t ip_encap;              /**< IP encapsulation */
        switch_mpls_encap_t mpls_encap;          /**< Mpls Encapsulation */
    } u;                                         /**< tunnel encap union */
    switch_handle_t out_if;                      /**< Underlying interface */
    struct {
        bool core_intf:1;                        /**< core interface */
        bool flood_enabled:1;                    /**< flooding enabled */
    } flags;                                     /**< tunnel flags */
} switch_tunnel_info_t;

/** Tunnel Egress type */
typedef enum switch_tunnel_type_egress_ {
    SWITCH_EGRESS_TUNNEL_TYPE_NONE           = 0,
    SWITCH_EGRESS_TUNNEL_TYPE_IPV4_VXLAN     = 1,
    SWITCH_EGRESS_TUNNEL_TYPE_IPV6_VXLAN     = 2,
    SWITCH_EGRESS_TUNNEL_TYPE_IPV4_GENEVE    = 3,
    SWITCH_EGRESS_TUNNEL_TYPE_IPV6_GENEVE    = 4,
    SWITCH_EGRESS_TUNNEL_TYPE_IPV4_NVGRE     = 5,
    SWITCH_EGRESS_TUNNEL_TYPE_IPV6_NVGRE     = 6,
    SWITCH_EGRESS_TUNNEL_TYPE_IPV4_ERSPAN_T3 = 7,
    SWITCH_EGRESS_TUNNEL_TYPE_IPV6_ERSPAN_T3 = 8,
    SWITCH_EGRESS_TUNNEL_TYPE_IPV4_GRE       = 9,
    SWITCH_EGRESS_TUNNEL_TYPE_IPV6_GRE       = 10,
    SWITCH_EGRESS_TUNNEL_TYPE_MPLS_L2VPN     = 13,
    SWITCH_EGRESS_TUNNEL_TYPE_MPLS_L3VPN     = 14,
    SWITCH_EGRESS_TUNNEL_TYPE_FABRIC         = 15,
    SWITCH_EGRESS_TUNNEL_TYPE_CPU            = 16,
    SWITCH_EGRESS_TUNNEL_TYPE_IPV4_VXLAN_GPE = 17,
} switch_tunnel_type_egress_t;

/** Tunnel Ingress type */
typedef enum switch_tunnel_type_ingress_ {
    SWITCH_INGRESS_TUNNEL_TYPE_NONE                    = 0,
    SWITCH_INGRESS_TUNNEL_TYPE_VXLAN                   = 1,
    SWITCH_INGRESS_TUNNEL_TYPE_GRE                     = 2,
    SWITCH_INGRESS_TUNNEL_TYPE_IP_IN_IP                = 3,
    SWITCH_INGRESS_TUNNEL_TYPE_GENEVE                  = 4,
    SWITCH_INGRESS_TUNNEL_TYPE_NVGRE                   = 5,
    SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L2VPN_NUM_LABELS_1 = 6,
    SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L2VPN_NUM_LABELS_2 = 7,
    SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L2VPN_NUM_LABELS_3 = 8,
    SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L3VPN_NUM_LABELS_1 = 9,
    SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L3VPN_NUM_LABELS_2 = 10,
    SWITCH_INGRESS_TUNNEL_TYPE_MPLS_L3VPN_NUM_LABELS_3 = 11,
    SWITCH_INGRESS_TUNNEL_TYPE_VXLAN_GPE               = 12,
} switch_tunnel_type_ingress_t;

/** Mpls ipv4 explicit null label */
#define SWITCH_MPLS_IPV4_EXPLICIT_NULL 0

/** Mpls ipv6 explicit null label */
#define SWITCH_MPLS_IPV6_EXPLICIT_NULL 2
    
/**
 Tunnel creation
 After tunnel creation another interface need to be created to offer
 L2 or L3 service on the tunnel
 @param device device
 @param direction allow for ingress or egress only interfaces
 @param tunnel_info tunnel encapsulation information
*/
switch_handle_t switch_api_tunnel_interface_create(switch_device_t device,
                                                  switch_direction_t direction,
                                                  switch_tunnel_info_t *tunnel_info);
    
/**
 Tunnel deletion
 No services should be configured on the tunnel when the tunnel is
 deleted
 @param device device
 @param tunnel_handle handle of tunnel returned on tunnel creation
*/
switch_status_t switch_api_tunnel_interface_delete(switch_device_t device,
                                                   switch_handle_t tunnel_handle);
    
/**
 Add member to logical network
 @param device device
 @param network_handle Logical network handle
 @param interface_handle Handle of access port ot Tunnel interface
*/
switch_status_t switch_api_logical_network_member_add(switch_device_t device,
                                                      switch_handle_t network_handle, 
                                                      switch_handle_t interface_handle);

/**
 Delete member from logical network
 @param device device
 @param network_handle Logical network handle
 @param interface_handle Handle of access port ot Tunnel interface
*/
switch_status_t switch_api_logical_network_member_remove(switch_device_t device,
                                                         switch_handle_t network_handle,
                                                         switch_handle_t interface_handle);

/**
 Mpls Transit Create
 @param device device
 @param mpls_encap mpls info
*/
switch_status_t switch_api_mpls_tunnel_transit_create(switch_device_t device, switch_mpls_encap_t *mpls_encap);

/**
 Mpls Transit Create
 @param device device
 @param mpls_encap mpls info
*/
switch_status_t switch_api_mpls_tunnel_transit_delete(switch_device_t device, switch_mpls_encap_t *mpls_encap);
/** @} */ // end of Tunnel API
    
#ifdef __cplusplus
}
#endif

#endif /* defined(_switch_tunnel_h_) */
