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

#ifndef _switch_meter_h_
#define _switch_meter_h_

#include <stdio.h>

#include "switch_base_types.h"
#include "switch_handle.h"
#include "switch_status.h"
#include "switch_acl.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
/** @defgroup Switching Meters Switching API
 *  API functions listed to configure meters
 *  @{
 */ // begin of meters
 // meters

/** Meter mode */
typedef enum switch_meter_mode_ {
    SWITCH_METER_MODE_NONE,                          /**< none */
    SWITCH_METER_MODE_TWO_RATE_THREE_COLOR,          /**< two rate, three color */
    SWITCH_METER_MODE_STORM_CONTROL                  /**< storm control */
} switch_meter_mode_t;

/** Meter color mode */
typedef enum switch_meter_color_source_ {
    SWITCH_METER_COLOR_SOURCE_NONE,                  /**< none */
    SWITCH_METER_COLOR_SOURCE_BLIND,                 /**< color blind */
    SWITCH_METER_COLOR_SOURCE_AWARE                  /**< color source */
} switch_meter_color_source_t;

/** Meter type */
typedef enum switch_meter_type_ {
    SWITCH_METER_TYPE_NONE = 0,
    SWITCH_METER_TYPE_PACKETS = 1,
    SWITCH_METER_TYPE_BYTES = 2,
} switch_meter_type_t;

/* Meter color */
typedef enum switch_meter_color_ {
    SWITCH_METER_COLOR_GREEN,
    SWITCH_METER_COLOR_YELLOW,
    SWITCH_METER_COLOR_RED,
    SWITCH_METER_COLOR_MAX
} switch_meter_color_t;

typedef enum switch_meter_stats_ {
    SWITCH_METER_STATS_GREEEN,
    SWITCH_METER_STATS_YELLOW,
    SWITCH_METER_STATS_RED,
    SWITCH_METER_STATS_MAX
} switch_meter_stats_t;

/** committed burst size */
typedef uint64_t switch_cbs_t;

/** peak burst size */
typedef uint64_t switch_pbs_t;

/** committed information rate */
typedef uint64_t switch_cir_t;

/** peak information rate */
typedef uint64_t switch_pir_t;

/** Meter attributes */
typedef struct switch_api_meter_{
    switch_meter_mode_t meter_mode;                            /**< meter mode */
    switch_meter_color_source_t color_source;                  /**< color source */
    switch_meter_type_t meter_type;                            /**< meter type */
    switch_cbs_t cbs;                                          /**< committed burst size */
    switch_pbs_t pbs;                                          /**< peak burst size */
    switch_cir_t cir;                                          /**< committed information rate */
    switch_pir_t pir;                                          /**< peak information rate */
    switch_acl_action_t action[SWITCH_METER_COLOR_MAX];        /**< packet action */
} switch_api_meter_t;

/**
 Create Meter
 @param device - device
 @param api_meter_info - contains meter attributes
*/
switch_handle_t switch_api_meter_create(switch_device_t device,
                                        switch_api_meter_t *api_meter_info);

/**
 Update Meter
 @param device - device
 @param meter_handle - meter handle
 @param api_meter_info - contains meter attributes
*/
switch_status_t switch_api_meter_update(switch_device_t device,
                                        switch_handle_t meter_handle,
                                        switch_api_meter_t *api_meter_info);

/**
 Delete Meter
 @param device- device
 @param meter_handle - meter handle
*/
switch_status_t switch_api_meter_delete(switch_device_t device,
                                        switch_handle_t meter_handle);

/**
 Meter stats
 @param device device
 @param meter_handle meter handle
 @param count number of counters
 @param counter_ids meter counter ids
 @param counters counter values
 */
switch_status_t
switch_api_meter_stats_get(switch_device_t device,
                          switch_handle_t meter_handle,
                          uint8_t count,
                          switch_meter_stats_t *counter_ids,
                          switch_counter_t *counters);

/** @} */ // end of meter

#ifdef __cplusplus
}
#endif

#endif /* defined(__switch_api__switch_meter__) */
