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

//
//  switch_handle.h
//
//
//  Created on 6/20/14.
//
//

#ifndef _switch_handle_h_
#define _switch_handle_h_

#include "switch_id.h"
#include <Judy.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    
typedef enum {
    SWITCH_HANDLE_TYPE_NONE,
    SWITCH_HANDLE_TYPE_PORT,
    SWITCH_HANDLE_TYPE_LAG,
    SWITCH_HANDLE_TYPE_INTERFACE,
    SWITCH_HANDLE_TYPE_VRF,
    SWITCH_HANDLE_TYPE_BD,
    SWITCH_HANDLE_TYPE_TUNNEL,
    SWITCH_HANDLE_TYPE_NHOP,
    SWITCH_HANDLE_TYPE_ARP,
    SWITCH_HANDLE_TYPE_MY_MAC,
    SWITCH_HANDLE_TYPE_LABEL,
    SWITCH_HANDLE_TYPE_STP,
    SWITCH_HANDLE_TYPE_MGID,
    SWITCH_HANDLE_TYPE_ACL,
    SWITCH_HANDLE_TYPE_MCAST_ECMP,
    SWITCH_HANDLE_TYPE_URPF,
    SWITCH_HANDLE_TYPE_MAX=20
} switch_handle_type_t;
    
/**
 Generic handle to encode different types of objects
 handle impicitly encodes the device, type and type specific
 */
 typedef unsigned long switch_handle_t;
    
 /** Handle related information */
typedef struct {
    switch_handle_type_t type;             /**< type of handle */
    switch_api_id_allocator *allocator;    /**< allocator associated with handle */
    unsigned int num_in_use;               /**< number of handle in use */
    unsigned int initial_size;             /**< current size of allocator */
} switch_handle_info_t;
    
// Protoypes
int switch_handle_type_init(switch_handle_type_t type, unsigned int size);
void switch_handle_type_free(switch_handle_type_t type);
switch_handle_t switch_handle_allocate(switch_handle_type_t type);
void switch_handle_free(switch_handle_t handle);
switch_handle_type_t switch_handle_get_type(switch_handle_t handle);
    
// Easy use macros
#define SWITCH_API_INVALID_HANDLE 0xFFFFFFFF
#define SWITCH_HW_INVALID_HANDLE 0xFFFFFFFF
    
#define _switch_handle_create(_type, _info, _judy, _init, _handle)      \
    _handle = switch_handle_allocate(_type);                            \
    if(_handle) {                                                       \
        _info *_i_info = switch_malloc(sizeof(_info), 1);               \
        if(_i_info) {                                                   \
            char *_ap=NULL;                                             \
            memset(_i_info, 0, sizeof(_info));                          \
            JLI(_ap, _judy, (unsigned int)_handle);                     \
            if(_ap) {                                                   \
                *(unsigned long *)_ap = (unsigned long)_i_info;         \
            } else {                                                    \
                switch_free(_i_info);                                   \
                switch_handle_free(_handle);                            \
                 _handle = 0;                                           \
            }                                                           \
        } else {                                                        \
            switch_handle_free(_handle);                                \
            _handle = 0;                                                \
        }                                                               \
    }                                                                   \
    
#define _switch_handle_delete(_info, _judy, _handle)                    \
    _info *_handle_info;                                                \
    int _ret = 0;                                                       \
    void *_dp=NULL;                                                     \
    JLG(_dp, _judy, (unsigned int)_handle);                             \
    if((_handle_info = (_info *) (*(unsigned long *)_dp))) {            \
        JLD(_ret, _judy, (unsigned int)_handle);                        \
        switch_free(_handle_info);                                      \
    }                                                                   \
    switch_handle_free(_handle);                                        \
    
#define _switch_handle_get(_info, _judy, _handle, _handle_info)         \
    void *_gp=NULL;                                                     \
    JLG(_gp, _judy, (unsigned int)_handle);                             \
    if (_gp)                                                            \
        _handle_info = (_info *) (*(unsigned long *)_gp);               \

#define switch_handle_get_first(_judy, _handle)                         \
    int ret = 0;                                                        \
    J1F(ret, _judy, _handle);                                           \
    if (!ret) {                                                         \
        _handle = 0;                                                    \
    }

#define switch_handle_get_next(_judy, old_handle, new_handle)           \
    int ret = 0;                                                        \
    new_handle = 0;                                                     \
    J1N(ret, _judy, old_handle);                                        \
    if (ret) {                                                          \
        new_handle = old_handle;                                        \
    }

#define SWITCH_HANDLE_IS_LAG(handle) \
    switch_handle_get_type(handle) == SWITCH_HANDLE_TYPE_LAG
    
#define SWITCH_HANDLE_IS_VRF(handle) \
    switch_handle_get_type(handle) == SWITCH_HANDLE_TYPE_VRF

#define SWITCH_HANDLE_IS_BD(handle) \
    switch_handle_get_type(handle) == SWITCH_HANDLE_TYPE_BD

#ifdef __cplusplus
}
#endif

#endif
