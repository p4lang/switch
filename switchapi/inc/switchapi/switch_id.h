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

#ifndef _switch_id_h_
#define _switch_id_h_

#include "switch_base_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    
/** ID allocator */
typedef struct switch_api_id_allocator_ {
    uint32_t n_words;            /**< number fo 32 bit words in allocator */
    uint32_t *data;              /**< bitmap of allocator */
    bool zero_based;             /**< allocate index from zero if set */
} switch_api_id_allocator;
    
/**
 Create a new allocator
 @param initial_size init size in words (32-bit) for allocator
 @param zero_based allocate index from 0 if set to true
*/
switch_api_id_allocator *switch_api_id_allocator_new(unsigned int initial_size, bool zero_based);
    
/**
 Delete the allocator
 @param allocator allocator allocated with create
*/
void switch_api_id_allocator_destroy(switch_api_id_allocator *allocator);
    
/**
 Allocate one id from the allocator
 @param allocator allocator created with create
*/
unsigned int switch_api_id_allocator_allocate (switch_api_id_allocator *allocator);

/**
 Allocate count consecutive ids from the allocator
 @param allocator allocator created with create
 @param count number of consecutive ids to allocate
*/
unsigned int switch_api_id_allocator_allocate_contiguous (switch_api_id_allocator *allocator, uint8_t count);
    
/**
 Free up id in allocator
 @param allocator allocator created with create
 @param id id to free in allocator
*/
void switch_api_id_allocator_release (switch_api_id_allocator *allocator, unsigned int id);
    
/**
 Set a bit in allocator
 @param allocator - bitmap allocator reference
 @param id - bit to be set in allocator
*/
void switch_api_id_allocator_set (switch_api_id_allocator *allocator, unsigned int id);

/**
 Check if a bit is set in allocator
 @param allocator - bitmap allocator reference
 @param id - bit to be checked in allocator
*/
int switch_api_id_allocator_is_set (switch_api_id_allocator *allocator, unsigned int id);

#ifdef __cplusplus
}
#endif

#endif
