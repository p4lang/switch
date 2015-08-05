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

#ifndef _switch_mirror_h
#define _switch_mirror_h

#include "switch_base_types.h"
#include "switch_handle.h"
#include "p4_sim/mirroring.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    
/**
*   @defgroup Mirror Mirroring API
*  API functions define and manipulate Access lists
*  @{
*/
// begin of MIRROR API

/** Mirror ID */
typedef unsigned int switch_mirror_id_t;

/** Mirror Session type */
typedef enum {
    SWITCH_MIRROR_TYPE_SIMPLE,      /**< Simple Mirror session */
    SWITCH_MIRROR_TYPE_TRUNCATE,    /**< Truncate packet in session */
    SWITCH_MIRROR_TYPE_COALESCE     /**< Coalesce mirrorred packets */
} switch_mirror_type_t;

/**
* ID for negative mirror session
*/
#define SWITCH_NEGATIVE_MIRROR_SID  1015

/**
 Create a mirror sesion
 @param device device on which to create mirror session
 @param id required id to identify the session
 @param direction ingress/egress
 @param eg_port egress port to mirror into
 @param type type of mirror session
 @param cos cos
 @param length Max length of packet
 @param timeout Timeout to flush packet
*/

switch_status_t switch_mirror_session_create(switch_device_t device, switch_mirror_id_t id,
                   switch_direction_t direction, switch_port_t eg_port,
                   switch_mirror_type_t type, switch_cos_t cos,
                   unsigned int length,
                   unsigned int timeout);

/**
 Update a mirror sesion
 @param device device on which to create mirror session
 @param id required id to identify the session
 @param direction ingress/egress
 @param eg_port egress port to mirror into
 @param type type of mirror session
 @param cos cos
 @param length Max length of packet
 @param timeout Timeout to flush packet
 @param enable enable
*/
switch_status_t switch_mirror_session_update(switch_device_t device, switch_mirror_id_t id,
                   switch_direction_t direction, switch_port_t eg_port,
                   switch_mirror_type_t type, switch_cos_t cos,
                   unsigned int length,
                   unsigned int timeout, int enable);
/**
 delete the mirror session
 @param device device
 @param id value used to create mirror session
*/
switch_status_t switch_mirror_session_delete(switch_device_t device, switch_mirror_id_t id);

/**
 Create mirror nhop
 @param device device
 @param id mirror session id
 @param nhop_hdl nhop handle
 */
switch_status_t switch_mirror_nhop_create(switch_device_t device, switch_mirror_id_t id, switch_handle_t nhop_hdl);

/**
 Delete mirror nhop
 @param device device
 @param id mirror session id
 */
switch_status_t switch_mirror_nhop_delete(switch_device_t device, switch_mirror_id_t id);

/** @} */ // end of ACL API

#ifdef __cplusplus
}
#endif

#endif
