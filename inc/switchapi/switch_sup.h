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

#ifndef _switch_sup_h_
#define _switch_sup_h_

#include "switch_base_types.h"
#include "switch_handle.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
 
/**
    CPU header
*/
typedef struct {
    uint16_t ether_type; /**< Special CPU Ether type to distinguish CPU pkts */
    uint8_t qid;        /**< queue id */
    uint16_t reason_code;   /**< reason for landing up in the CPU */
    uint16_t rxhash;        /**< Unused */
    switch_handle_t bridge_domain; /**< bridge domain (vlan) handle */
    switch_handle_t ingress_lif;   /**< Ingress interface */
    switch_handle_t egress_lif;    /**< Egress interface */
    uint8_t lu_bypass_ingress;  /**< Ingress bypass */
    uint8_t lu_bypass_egress;   /**< Egress bypass */
} switch_cpu_header_t;

/** Callback reason to register for */
// TBD Need to enumerate/encode
typedef unsigned int switch_callback_reason_t;


/** CPU Rx Callback */
typedef switch_status_t (*switch_cpu_rx_callback_fn)(switch_cpu_header_t *cpu_header, void *pkt, void *data);

/** CPU Tx Callback */
typedef switch_status_t (*switch_cpu_tx_callback_fn)(switch_cpu_header_t *cpu_header, void *pkt, void *data);

/**
Register for callback on reception of packets qualified by reason
@param device device to register callback
@param cb_fn callback function pointer
@param reason reason code on which to call
@param data opaque data to be called with (not used by the API)
*/
switch_status_t switch_api_register_rx_callback(switch_device_t device, switch_cpu_rx_callback_fn cb_fn, switch_callback_reason_t reason, void *data);

/**
Deregister for callback on reception of packets qualified by reason
@param device device to register callback
@param cb_fn callback function pointer
@param reason reason code on which to call
*/
switch_status_t switch_api_deregister_rx_callback(switch_device_t device, switch_cpu_rx_callback_fn cb_fn, switch_callback_reason_t reason);

/**
Notify the completion of rx
@param device device
@param pkt packet obtained thorugh the recieve callback
*/
switch_status_t switch_api_rx_done(switch_device_t device, void *pkt);

/**
Allocate packe memory to transmit
@param device device
@param pointer of packet allocated to be returned in
*/
switch_status_t switch_api_tx_packet_alloc(switch_device_t device, void **pkt);

/**
Transmit a packet
@param device device
@param cpu cpu header of packet relevant
@param pkt packet buffer to transmit (obtained through packet_alloc)
@param cb_fn Optional callback for notification of Tx completion (could be NULL)
@param data Optional data to be sent with callback (could be NULL)
*/

switch_status_t switch_api_tx_packet(switch_device_t device, switch_cpu_header_t *cpu, void *pkt, switch_cpu_tx_callback_fn cb_fn, void *data);

/**
 Rewrite packet from/to supervisor
 @param device  - Device number
 @param port_id - CPU port id
 */
switch_status_t switch_api_sup_rewrite_init(switch_device_t device, switch_port_t port_id);

#ifdef __cplusplus
}
#endif

#endif
