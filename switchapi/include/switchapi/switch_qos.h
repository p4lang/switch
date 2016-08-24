/*
Copyright 2013-present Barefoot Networks, Inc.
*/

#ifndef _switch_qos_h_
#define _switch_qos_h_

#include "switch_base_types.h"
#include "switch_handle.h"
#include "switch_meter.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @defgroup QOS QOS API
 *  API functions to create buffers and qos maps
 *  @{
 */  // begin of QOS API

// QOS
/** QOS information */

typedef enum switch_qos_map_ingress_ {
  SWITCH_QOS_MAP_INGRESS_NONE = 0,
  SWITCH_QOS_MAP_INGRESS_DSCP_TO_TC = 1,
  SWITCH_QOS_MAP_INGRESS_PCP_TO_TC = 2,
  SWITCH_QOS_MAP_INGRESS_DSCP_TO_COLOR = 3,
  SWITCH_QOS_MAP_INGRESS_PCP_TO_COLOR = 4,
  SWITCH_QOS_MAP_INGRESS_DSCP_TO_TC_AND_COLOR = 5,
  SWITCH_QOS_MAP_INGRESS_PCP_TO_TC_AND_COLOR = 6,
  SWITCH_QOS_MAP_INGRESS_TC_TO_ICOS = 7,
  SWITCH_QOS_MAP_INGRESS_TC_TO_QUEUE = 8,
  SWITCH_QOS_MAP_INGRESS_TC_TO_ICOS_AND_QUEUE = 9
} switch_qos_map_ingress_t;

typedef enum switch_qos_map_egress_ {
  SWITCH_QOS_MAP_EGRESS_NONE = 0,
  SWITCH_QOS_MAP_EGRESS_TC_TO_DSCP = 1,
  SWITCH_QOS_MAP_EGRESS_TC_TO_PCP = 2,
  SWITCH_QOS_MAP_EGRESS_COLOR_TO_DSCP = 3,
  SWITCH_QOS_MAP_EGRESS_COLOR_TO_PCP = 4,
  SWITCH_QOS_MAP_EGRESS_TC_AND_COLOR_TO_DSCP = 5,
  SWITCH_QOS_MAP_EGRESS_TC_AND_COLOR_TO_PCP = 6
} switch_qos_map_egress_t;

typedef struct switch_qos_map_ {
  uint8_t dscp;
  uint8_t pcp;
  uint16_t tc;
  switch_color_t color;
  uint8_t icos;
  uint8_t qid;
} switch_qos_map_t;

/**
 Create ingress qos map
 @param device device
 @param qos_map QOS map
*/
switch_handle_t switch_api_qos_map_ingress_create(
    switch_device_t device,
    switch_qos_map_ingress_t map_type,
    uint8_t num_entries,
    switch_qos_map_t *qos_map);

/**
 Delete ingress qos map
 @param device device
 @param qos_map_handle Qos map handle
*/
switch_status_t switch_api_qos_map_ingress_delete(
    switch_device_t device, switch_handle_t qos_map_handle);

/**
 Create egress qos map
 @param device device
 @param qos_map QOS map
*/
switch_handle_t switch_api_qos_map_egress_create(
    switch_device_t device,
    switch_qos_map_egress_t map_type,
    uint8_t num_entries,
    switch_qos_map_t *qos_map);

/**
 Delete ingress qos map
 @param device device
 @param qos_map_handle Qos map handle
*/
switch_status_t switch_api_qos_map_egress_delete(
    switch_device_t device, switch_handle_t qos_map_handle);

/**
 Update qos map
 @param device device
 @param qos_map_handle Qos map handle
 @param qos_map QOS map
*/
switch_status_t switch_api_qos_map_update(switch_device_t device,
                                          switch_handle_t qos_map_handle,
                                          uint8_t num_entries,
                                          switch_qos_map_t *qos_map);

/** @} */  // end of QOS API

#ifdef __cplusplus
}
#endif

#endif
