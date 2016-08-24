/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2015-2016 Barefoot Networks, Inc.

 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks,
 * Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material is
 * strictly forbidden unless prior written permission is obtained from
 * Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a
 * written agreement with Barefoot Networks, Inc.
 *
 * $Id: $
 *
 ******************************************************************************/

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"
#include "switchapi/switch_nat.h"
#include "switchapi/switch_status.h"
#include "switchapi/switch_interface.h"
#include "switchapi/switch_utils.h"
#include "switch_nhop_int.h"
#include "switch_pd.h"
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

static tommy_hashtable switch_nat_hash_table;
static switch_api_id_allocator *nat_rw_alloc;

#define SWITCH_NAT_HASH_TABLE_SIZE 1024
#define SWITCH_NAT_REWRITE_TABLE_SIZE (16 * 1024)

switch_status_t switch_nat_init(switch_device_t device) {
  UNUSED(device);
  tommy_hashtable_init(&switch_nat_hash_table, SWITCH_NAT_HASH_TABLE_SIZE);
  nat_rw_alloc = switch_api_id_allocator_new(
      SWITCH_NAT_REWRITE_TABLE_SIZE / sizeof(uint32_t), false);
  return SWITCH_STATUS_SUCCESS;
}

switch_status_t switch_nat_free(switch_device_t device) {
  UNUSED(device);
  tommy_hashtable_done(&switch_nat_hash_table);
  return SWITCH_STATUS_SUCCESS;
}

static inline void switch_nat_hash_key_init(uchar *key,
                                            switch_api_nat_info_t *api_nat_info,
                                            uint32_t *len,
                                            uint32_t *hash) {
  *len = 0;
  memset(key, 0, SWITCH_NAT_HASH_KEY_SIZE);
  memcpy(key, &api_nat_info->vrf_handle, sizeof(switch_handle_t));
  *len += sizeof(switch_handle_t);

  if (SWITCH_NAT_TYPE_IS_VALID_SRC(api_nat_info)) {
    memcpy(&key[*len], &(SWITCH_NAT_SRC_IP(api_nat_info)), 4);
  }
  *len += 4;

  if (SWITCH_NAT_TYPE_IS_VALID_SRC_PORT(api_nat_info)) {
    memcpy(&key[*len], &api_nat_info->src_port, 2);
  }
  *len += 2;

  if (SWITCH_NAT_TYPE_IS_VALID_DST(api_nat_info)) {
    memcpy(&key[*len], &(SWITCH_NAT_DST_IP(api_nat_info)), 4);
  }
  *len += 4;

  if (SWITCH_NAT_TYPE_IS_VALID_DST_PORT(api_nat_info)) {
    memcpy(&key[*len], &api_nat_info->dst_port, 2);
  }
  *len += 2;

  if (SWITCH_NAT_TYPE_IS_VALID_SRC_PORT(api_nat_info) ||
      SWITCH_NAT_TYPE_IS_VALID_DST_PORT(api_nat_info)) {
    memcpy(&key[*len], &api_nat_info->protocol, 2);
  }
  *len += 2;

  memcpy(&key[*len], &api_nat_info->nat_rw_type, 1);
  *len += 1;

  *hash = MurmurHash2(key, *len, 0x98761234);
}

static inline int switch_nat_hash_cmp(const void *key1, const void *key2) {
  return memcmp(key1, key2, SWITCH_NAT_HASH_KEY_SIZE);
}

static switch_nat_info_t *switch_nat_insert_hash(
    switch_api_nat_info_t *api_nat_info) {
  switch_nat_info_t *nat_info = NULL;
  unsigned char key[SWITCH_NAT_HASH_KEY_SIZE];
  uint32_t len = 0;
  uint32_t hash = 0;

  switch_nat_hash_key_init(key, api_nat_info, &len, &hash);
  nat_info = switch_malloc(sizeof(switch_nat_info_t), 1);
  if (!nat_info) {
    return NULL;
  }
  memcpy(&nat_info->api_nat_info, api_nat_info, sizeof(switch_api_nat_info_t));
  memcpy(nat_info->key, key, SWITCH_NAT_HASH_KEY_SIZE);
  tommy_hashtable_insert(
      &switch_nat_hash_table, &(nat_info->node), nat_info, hash);
  return nat_info;
}

static switch_status_t switch_nat_delete_hash(
    switch_api_nat_info_t *api_nat_info) {
  switch_nat_info_t *nat_info = NULL;
  unsigned char key[SWITCH_NAT_HASH_KEY_SIZE];
  uint32_t len = 0;
  uint32_t hash = 0;

  switch_nat_hash_key_init(key, api_nat_info, &len, &hash);
  nat_info = tommy_hashtable_remove(
      &switch_nat_hash_table, switch_nat_hash_cmp, key, hash);
  if (!nat_info) {
    return SWITCH_STATUS_ITEM_NOT_FOUND;
  }
  switch_free(nat_info);
  return SWITCH_STATUS_SUCCESS;
}

static switch_nat_info_t *switch_nat_search_hash(
    switch_api_nat_info_t *api_nat_info) {
  switch_nat_info_t *nat_info = NULL;
  unsigned char key[SWITCH_NAT_HASH_KEY_SIZE];
  uint32_t len = 0;
  uint32_t hash = 0;

  switch_nat_hash_key_init(key, api_nat_info, &len, &hash);
  nat_info = tommy_hashtable_search(
      &switch_nat_hash_table, switch_nat_hash_cmp, key, hash);
  return nat_info;
}

switch_status_t switch_api_nat_add(switch_device_t device,
                                   switch_api_nat_info_t *api_nat_info) {
  switch_interface_info_t *intf_info = NULL;
  switch_nat_info_t *nat_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;
  bool add = true;

  nat_info = switch_nat_search_hash(api_nat_info);
  if (nat_info) {
    add = false;
  } else {
    nat_info = switch_nat_insert_hash(api_nat_info);
    if (!nat_info) {
      return SWITCH_STATUS_NO_MEMORY;
    }
    nat_info->nat_rw_index = switch_api_id_allocator_allocate(nat_rw_alloc);
  }

#ifdef SWITCH_PD
  if (add) {
    status = switch_pd_nat_table_add_entry(
        device, intf_info, nat_info, &nat_info->hw_entry);
    status = switch_pd_nat_rewrite_table_add_entry(
        device, nat_info, &nat_info->rw_hw_entry);
  } else {
  }
#endif

  return status;
}

switch_status_t switch_api_nat_delete(switch_device_t device,
                                      switch_api_nat_info_t *api_nat_info) {
  switch_nat_info_t *nat_info = NULL;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  nat_info = switch_nat_search_hash(api_nat_info);
  if (!nat_info) {
    return SWITCH_STATUS_ITEM_NOT_FOUND;
  }
  switch_api_id_allocator_release(nat_rw_alloc, nat_info->nat_rw_index);

#ifdef SWITCH_PD
  status =
      switch_pd_nat_table_delete_entry(device, nat_info, nat_info->hw_entry);
  status =
      switch_pd_nat_rewrite_table_delete_entry(device, nat_info->rw_hw_entry);
#endif

  status = switch_nat_delete_hash(api_nat_info);
  return status;
}

#ifdef __cplusplus
}
#endif
