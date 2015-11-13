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

#ifndef _switch_vrf_h_
#define _switch_vrf_h_

#include "switch_handle.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    
//VRF
/** @defgroup VRF VRF API
 *  API functions define and manipulate vrf
 *  @{
 */ // begin of VRF API

/** VRF information */
typedef struct switch_vrf_info_ {
    switch_vrf_id_t vrf_id;      /**< user VRF */
    switch_mac_addr_t mac;       /**< mac address */
    struct {
        uint8_t v4_enabled;      /**< v4 enable */
        uint8_t v6_enabled;      /**< v6 enable */
        uint8_t vrf_type;        /**< core or edge vrf */
    } flags;                     /**< vrf flags */
} switch_vrf_info_t;

/** Vrf type */
typedef enum switch_vrf_type_
{
    SWITCH_VRF_TYPE_CORE,            /**< core vrf */
    SWITCH_VRF_TYPE_EDGE             /**< edge vrf */
} switch_vrf_type_t;

/** Vrf attributes */
typedef enum switch_vrf_attr_
{
    SWITCH_VRF_ATTR_VRF_TYPE                             /**< Vrf type - edge or core */
} switch_vrf_attr_t;

/**
  Create a VRF
  @param device - device that programs the VRF
  @param vrf_id - Vrf Id
*/
switch_handle_t switch_api_vrf_create(switch_device_t device, switch_vrf_id_t vrf_id);

/**
  Delete a VRF
  @param device - device that programs the VRF
  @param vrf_handle Vrf handle
*/
switch_status_t switch_api_vrf_delete(switch_device_t device, switch_handle_t vrf_handle);

/**
  Set an attribute for a Vrf
  @param vrf_handle - vrf handle that identifes vrf uniquely
  @param attr_type - Attribute Type
  @param value - Value of the attribute
*/
switch_status_t switch_api_vrf_attribute_set(switch_handle_t vrf_handle,
                                     switch_vrf_attr_t attr_type,
                                     uint64_t value);

/**
  Get an attribute for a Vrf
  @param vrf_handle - vrf handle that identifes vrf uniquely
  @param attr_type - Attribute Type
  @param value - Value of the attribute
*/
switch_status_t switch_api_vrf_attribute_get(switch_handle_t vrf_handle,
                                     switch_vrf_attr_t attr_type,
                                     uint64_t *value);

/**
  Set vrf type on vrf
  @param vrf_handle - vrf handle that identifies vrf uniquely
  @param value - Value of vrf type
*/
switch_status_t switch_api_vrf_type_set(switch_handle_t vrf_handle, uint64_t value);

/**
  Get vrf type on vrf
  @param vrf_handle - vrf handle that identifies vrf uniquely
  @param value - Value of vrf type
*/
switch_status_t switch_api_vrf_type_get(switch_handle_t vrf_handle, uint64_t *value);

/** @} */ // end of VRF API

#ifdef __cplusplus
}
#endif

#endif
