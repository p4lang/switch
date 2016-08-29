/*
 * Copyright 2015-present Barefoot Networks, Inc.
 */

#ifndef _switch_sflow_h
#define _switch_sflow_h

#include "switch_base_types.h"
#include "switch_handle.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Maximum sflow session */
#define SWITCH_MAX_SFLOW_SESSIONS \
  16  // MAX_SFLOW_SESSIONS from p4_table_sizes.h

/** Maximum sflow access control entries */
#define SWITCH_MAX_SFLOW_ACES 512  // MAX_SFLOW_SESSIONS from p4_table_sizes.h

/** sflow match fields */
typedef enum switch_sflow_match_field_ {
  SWITCH_SFLOW_MATCH_PORT = 0,
  SWITCH_SFLOW_MATCH_VLAN,
  SWITCH_SFLOW_MATCH_SIP,
  SWITCH_SFLOW_MATCH_DIP,
  SWITCH_SFLOW_MATCH_FIELD_MAX,
} switch_sflow_match_field_t;

/** sflow match values */
typedef union switch_sflow_match_value_ {
  switch_handle_t port; /**< port handle */
  uint32_t vlan;        /**< vlan id */
  uint32_t sip;         /**< source ip */
  uint32_t dip;         /**< destination ip */
} switch_sflow_match_value_t;

/** sflow match mask - same as masks used for acl */
typedef union switch_sflow_match_mask_ {
  unsigned type : 1; /**< mask type */
  union {
    uint64_t mask;           /**< mask value */
    unsigned int start, end; /**< mask range */
  } u;                       /**< ip mask union */
} switch_sflow_match_mask_t;

/** Egress acl key value pair */
typedef struct switch_sflow_match_key_value_pair_ {
  switch_sflow_match_field_t field; /**< sflow match fields */
  switch_sflow_match_value_t value; /**< sflow match values */
  switch_sflow_match_mask_t mask;   /**< sflow match masks */
} switch_sflow_match_key_value_pair_t;

/** Sflow collector type */
typedef enum {
  SFLOW_COLLECTOR_TYPE_CPU = 0,
  SFLOW_COLLECTOR_TYPE_REMOTE
} switch_sflow_collector_type_e;

/** Sflow sampling mode */
typedef enum {
  SWITCH_SFLOW_SAMPLE_PKT = 0,
} switch_sflow_sample_mode_e;

/** sflow session struct */
typedef struct switch_api_sflow_session_info_ {
  uint32_t session_id;   /**< session id */
  uint32_t timeout_usec; /**< timeout 0 => 100us (default) */
  uint32_t sample_rate;  /**< sampling rate 0 => every 10k pkts (default) */
  uint32_t extract_len;  /**< extract length 0 => 80 (default) */
  switch_handle_t egress_port_hdl;              /**< egress port handle */
  switch_sflow_collector_type_e collector_type; /**< sflow collector type */
  switch_sflow_sample_mode_e sample_mode;       /**< sampling mode */
} switch_api_sflow_session_info_t;

/**
 sflow session create
 @param device device
 @param api_sflow_info sflow information
*/
switch_handle_t switch_api_sflow_session_create(
    switch_device_t device, switch_api_sflow_session_info_t *api_sflow_info);

/**
 sflow session delete
 @param device device
 @param sflow_hdl sflow handle
 @param all_cleanup all cleanup
*/
switch_status_t switch_api_sflow_session_delete(switch_device_t device,
                                                switch_handle_t sflow_hdl,
                                                bool all_cleanup);

/**
 sflow session attach
 @param device device
 @param sflow_hdl sflow handle
 @param direction direction
 @param priority priority
 @param sample_rate sampling rate
 @param key_value_count key value count
 @param kvp key value pair
 @param entry_hdl ace entry handle
*/
switch_status_t switch_api_sflow_session_attach(
    switch_device_t device,
    switch_handle_t sflow_hdl,
    switch_direction_t direction,
    unsigned int priority,
    unsigned int sample_rate,
    unsigned int key_value_count,
    switch_sflow_match_key_value_pair_t *kvp,
    switch_handle_t *entry_hdl);

/**
 sflow session detach
 @param device device
 @param sflow_hdl sflow handle
 @param entry_hdl ace entry handle
*/
switch_status_t switch_api_sflow_session_detach(switch_device_t device,
                                                switch_handle_t sflow_hdl,
                                                switch_handle_t entry_hdl);

switch_status_t switch_api_sflow_session_sample_count_get(
    switch_device_t device,
    switch_handle_t sflow_hdl,
    switch_handle_t entry_hdl,
    switch_counter_t *sample_pool);

switch_status_t switch_api_sflow_session_sample_count_reset(
    switch_device_t device,
    switch_handle_t sflow_hdl,
    switch_handle_t entry_hdl);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _switch_sflow_h */
