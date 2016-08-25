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
