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

#ifndef _switch_lpm_int_h_
#define _switch_lpm_int_h_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdbool.h>

typedef struct switch_lpm_trie_s switch_lpm_trie_t;

typedef unsigned long value_t;

switch_lpm_trie_t *switch_lpm_trie_create(size_t key_width_bytes,
                                          bool auto_shrink);

unsigned int switch_lpm_trie_size(switch_lpm_trie_t *t);

void switch_lpm_trie_destroy(switch_lpm_trie_t *t);

void switch_lpm_trie_insert(switch_lpm_trie_t *trie,
                            const char *prefix,
                            int prefix_length,
                            const value_t value);

bool switch_lpm_trie_has_prefix(const switch_lpm_trie_t *trie,
                                const char *prefix,
                                int prefix_length);

bool switch_lpm_trie_lookup(const switch_lpm_trie_t *trie,
                            const char *key,
                            value_t *pvalue);

bool switch_lpm_trie_delete(switch_lpm_trie_t *trie,
                            const char *prefix,
                            int prefix_length);

#ifdef __cplusplus
}
#endif

#endif
