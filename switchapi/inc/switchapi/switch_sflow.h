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

#define SWITCH_MAX_SFLOW_SESSIONS 16  // MAX_SFLOW_SESSIONS from sizes.h
#define SWITCH_MAX_SFLOW_ACES 512     // SFLOW_INGRESS_TABLE_SIZE from sizes.h

typedef enum switch_sflow_match_field_ {
  SWITCH_SFLOW_MATCH_PORT = 0,
  SWITCH_SFLOW_MATCH_VLAN,
  SWITCH_SFLOW_MATCH_SIP,
  SWITCH_SFLOW_MATCH_DIP,
  SWITCH_SFLOW_MATCH_FIELD_MAX,
} switch_sflow_match_field_t;

/* sflow match values */
typedef union switch_sflow_match_value_ {
  switch_handle_t port;
  uint32_t vlan;
  uint32_t sip;
  uint32_t dip;
} switch_sflow_match_value_t;

/* sflow match mask - same as masks used for acl */
typedef union switch_sflow_match_mask_ {
  unsigned type : 1; /**< mask type */
  union {
    uint64_t mask;           /**< mask value */
    unsigned int start, end; /**< mask range */
  } u;                       /**< ip mask union */
} switch_sflow_match_mask_t;

/** Egress acl key value pair */
typedef struct switch_sflow_match_key_value_pair_ {
  switch_sflow_match_field_t field;
  switch_sflow_match_value_t value;
  switch_sflow_match_mask_t mask;
} switch_sflow_match_key_value_pair_t;

typedef enum {
  SFLOW_COLLECTOR_TYPE_CPU = 0,
  SFLOW_COLLECTOR_TYPE_REMOTE
} switch_sflow_collector_type_e;

typedef enum {
  SWITCH_SFLOW_SAMPLE_PKT = 0,
} switch_sflow_sample_mode_e;

typedef struct switch_api_sflow_session_info_ {
  uint32_t session_id;
  uint32_t timeout_usec;  // 0 => 100us (default)
  uint32_t sample_rate;   // 0 => every 10k pkts (default)
  uint32_t extract_len;   // 0 => 80 (default)
  switch_handle_t egress_port_hdl;
  switch_sflow_collector_type_e collector_type;
  switch_sflow_sample_mode_e sample_mode;
} switch_api_sflow_session_info_t;

switch_handle_t switch_api_sflow_session_create(
    switch_device_t device, switch_api_sflow_session_info_t *api_sflow_info);
switch_status_t switch_api_sflow_session_delete(switch_device_t device,
                                                switch_handle_t sflow_hdl,
                                                bool all_cleanup);

switch_status_t switch_api_sflow_session_attach(
    switch_device_t device,
    switch_handle_t sflow_hdl,
    switch_direction_t direction,
    unsigned int priority,
    unsigned int
        sample_rate, /* != 0 can override sampling rate of the session */
    unsigned int key_value_count,
    switch_sflow_match_key_value_pair_t *kvp,
    switch_handle_t *entry_hdl);

switch_status_t switch_api_sflow_session_detach(switch_device_t device,
                                                switch_handle_t sflow_hdl,
                                                switch_handle_t entry_hdl);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _switch_sflow_h */
