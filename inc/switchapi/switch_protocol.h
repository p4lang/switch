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

#ifndef _switch_protocol_h
#define _switch_protocol_h

#include "switch_handle.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @defgroup Protocol Protocol types and info
 * Protocol types and info
 *  @{
 */ // begin of Protocol API

/** Encap type */
typedef enum switch_encap_type_ {
    SWITCH_API_ENCAP_TYPE_NONE=0,       /**< Not a tunnel */
    SWITCH_API_ENCAP_TYPE_VLAN=1,       /**< VLAN encapsulation */
    SWITCH_API_ENCAP_TYPE_QINQ=2,       /**< Double Tag encap */
    SWITCH_API_ENCAP_TYPE_VXLAN=3,      /**< VxLAN encapsulation */
    SWITCH_API_ENCAP_TYPE_GRE=4,        /**< GRE encapsulation */
    SWITCH_API_ENCAP_TYPE_NVGRE=5,      /**< NVGRE encapsulation */
    SWITCH_API_ENCAP_TYPE_GENEVE=6,     /**< Geneve encapsulation */
    SWITCH_API_ENCAP_TYPE_ERSPAN_T3=7   /**< ERSPAN type III encapsulation */
} switch_encap_type_t;

/** UDP fields that are relevant */
typedef struct switch_udp_ {
    uint16_t src_port;                         /**< Source port number */
    uint16_t dst_port;                         /**< Destination port number */
} switch_udp_t;

/** TCP fields that are relevant */
typedef struct switch_tcp_ {
    uint16_t src_port;                         /**< Source port number */
    uint16_t dst_port;                         /**< Destination port number */
} switch_tcp_t;

/** QinQ encapsulation format */
typedef struct {
    switch_vlan_t outer;                          /**< outer tag */
    switch_vlan_t inner;                          /**< Inner tag */
} switch_qinq_t;

/** VxLAN identifier */
typedef struct {
    unsigned int vnid:24;                     /**< Unique value for a tenant */
    unsigned int rsvd:8;                      /**< unused - should be 0 */
} switch_vxlan_id_t;

/** NvGRE identifier */
typedef struct {
    unsigned int tnid:24;                     /**< Unique value for a tenant */
    unsigned int rsvd:8;                      /**< unused - should be 0 */
} switch_nvgre_id_t;

/** Geneve identifier */
typedef struct {
    unsigned int version:2,                   /**< version - set to 0 */
                 option_length:6,             /**< option length */
                 oam:1,                       /**< OAM Pkt */
                 critical:1,                  /**< Critical */
                 rsvd:6,                      /**< reserved data should be 0 */
                 prototype:16;                /**< ether type */
    unsigned int vni:24,                      /**< Tenant ID */
                 rsvd2:8;                     /**< reserved should be 0 */
} switch_geneve_id_t;

/** Gre identifier */
typedef struct {
    unsigned short csum_present: 1,            /**< Checksum present? */
                    routing_present:1,         /**< Routing info present? */
                    key_present: 1,            /**< Key present? */
                    sequence_present: 1,       /**< Sequence present? */
                    strict_route: 1,           /**< strict route? */
                    recursion_control: 1,      /**< recursion control */
                    flags: 5,                  /**< flags */
                    version: 3;                /**< version */
    unsigned short  protocol;                  /**< ether type */
    unsigned short  checksum;                  /**< checksum of packet (opt) */
    unsigned short  offset;                    /**< offset in packet */
    unsigned int    key;                       /**< GRE key */
    unsigned int    sequence;                  /**< sequence number */
    unsigned int    routing;                   /**< Routing information */
} switch_gre_t;

/** IP Header information relevant */
typedef struct switch_ip_encap_ {
    switch_handle_t vrf_handle;              /**< VRF instance */
    switch_ip_addr_t src_ip;                 /**< Source IP address of tunnel */
    switch_ip_addr_t dst_ip;                 /**< Destination IP of tunnel */
    unsigned short mtu;                      /**< IP MTU supported */
    unsigned char ttl;                       /**< Time to live */
    unsigned char proto;                     /**< UDP/TCP/GRE */
    union {
        switch_udp_t udp;                    /**< UDP header */
        switch_tcp_t tcp;                    /**< TCP header */
        switch_gre_t gre;                    /**< IP GRE header */
    } u;                                     /**< union */
} switch_ip_encap_t;

/** Maximum mpls labels supported */
#define SWITCH_MPLS_LABEL_MAX 5

/** Mpls header */
typedef struct switch_mpls_ {
    unsigned int label:20;                    /**< mpls label */
    unsigned int exp:3;                       /**< experimental */
    unsigned int bos:1;                       /**< bottom of stack */
    unsigned int ttl:8;                       /**< time to live */
} switch_mpls_t;

/** Mpls tunnel type */
typedef enum switch_mpls_type_ {
    SWITCH_API_MPLS_TYPE_EOMPLS,
    SWITCH_API_MPLS_TYPE_IPV4_MPLS,
    SWITCH_API_MPLS_TYPE_IPV6_MPLS,
    SWITCH_API_MPLS_TYPE_VPLS,
    SWITCH_API_MPLS_TYPE_PW
} switch_mpls_type_t;

/** Mpls mode */
typedef enum switch_mpls_mode_ {
    SWITCH_API_MPLS_INITIATE,
    SWITCH_API_MPLS_TRANSIT,
    SWITCH_API_MPLS_TERMINATE
} switch_mpls_mode_t;

/** Mpls action */
typedef enum switch_mpls_action_ {
    SWITCH_API_MPLS_ACTION_POP,
    SWITCH_API_MPLS_ACTION_PUSH,
    SWITCH_API_MPLS_ACTION_SWAP,
    SWITCH_API_MPLS_ACTION_SWAP_PUSH
} switch_mpls_action_t;

/** Mpls swap identifier */
typedef struct switch_mpls_swap_ {
    switch_mpls_t old_tag;                       /**< old mpls header */
    switch_mpls_t new_tag;                       /**< new mpls header */
} switch_mpls_swap_t;

/** Mpls pop identifier */
typedef struct switch_mpls_pop_ {
    switch_mpls_t tag[SWITCH_MPLS_LABEL_MAX];        /**< mpls header stack to pop */
    uint8_t count;                           /**< number of label stack to pop */
} switch_mpls_pop_t;

/** Mpls push identifier */
typedef struct switch_mpls_push_ {
    switch_mpls_t tag[SWITCH_MPLS_LABEL_MAX];       /**< mpls header stack to push */
    uint8_t count;                          /**< number of label stack to push */
} switch_mpls_push_t;

/** Mpls swap identifier */
typedef struct switch_mpls_swap_push_ {
    switch_mpls_t old_tag;                      /**< old mpls header */
    switch_mpls_t new_tag[SWITCH_MPLS_LABEL_MAX];   /**< new mpls header stack to push */
    uint8_t count;                          /**< number of label stack to push */
} switch_mpls_swap_push_t;

/** Mpls encap identifer */
typedef struct switch_mpls_encap_ {
    switch_mpls_type_t mpls_type;                   /**< mpls tunnel type */
    switch_mpls_action_t mpls_action;               /**< mpls action - push/pop/swap */
    switch_mpls_mode_t mpls_mode;                   /**< mpls mode */
    union {
        switch_mpls_swap_t swap_info;               /**< mpls swap info */
        switch_mpls_push_t push_info;               /**< mpls push info */
        switch_mpls_pop_t pop_info;                 /**< mpls pop info */
        switch_mpls_swap_push_t swap_push_info;     /**< mpls swap push info */
    } u;                                        /**< union */
    switch_handle_t bd_handle;                      /**< bridge domain handle */
    switch_handle_t vrf_handle;                     /**< vrf handle */
    switch_handle_t nhop_handle;                    /**< nexthop handle */
    switch_handle_t egress_if;                      /**< egress interface handle */
} switch_mpls_encap_t;

/** Tunnel encap identifier */
typedef struct switch_encap_info_ {
    switch_encap_type_t encap_type;               /**< Encap type */
    union {
        switch_vlan_t vlan_id;                    /**< VLAN Id*/
        switch_vxlan_id_t vxlan_info;             /**< VxLAN domain info */
        switch_geneve_id_t geneve_info;           /**< Geneve domain info */
        switch_nvgre_id_t nvgre_info;             /**< NVGRE domain info */
        switch_qinq_t qinq_info;                  /**< Qinq info */
        uint32_t tunnel_vni;                  /**< Tunnel Vni - Used only in LN Basic mode */
    } u;                                      /**< union */
} switch_encap_info_t;

/** @} */ // end of Protocol 
    
#ifdef __cplusplus
}
#endif

#endif
