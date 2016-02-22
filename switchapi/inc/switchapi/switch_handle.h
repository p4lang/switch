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
    SWITCH_HANDLE_TYPE_HOSTIF_GROUP,
    SWITCH_HANDLE_TYPE_HOSTIF,
    SWITCH_HANDLE_TYPE_ACE,
    SWITCH_HANDLE_TYPE_MIRROR,
    SWITCH_HANDLE_TYPE_METER,
    SWITCH_HANDLE_TYPE_SFLOW,
    SWITCH_HANDLE_TYPE_LAG_MEMBER,
    SWITCH_HANDLE_TYPE_ACL_COUNTER,

    SWITCH_HANDLE_TYPE_MAX=32
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
    unsigned int num_handles;              /**< number of handles to allocate */
    bool grow_on_demand;                   /**< allocate new handles as needed */
    bool zero_based;                       /**< 0 is a valid id */
} switch_handle_info_t;

// Protoypes
int switch_handle_type_init(switch_handle_type_t type, unsigned int size);
int switch_handle_type_allocator_init(switch_handle_type_t type,
                                      unsigned int num_handles,
                                      bool grow_on_demand, bool zero_based);
void switch_handle_type_free(switch_handle_type_t type);
switch_handle_t switch_handle_allocate(switch_handle_type_t type);
switch_handle_t switch_handle_set_and_allocate(switch_handle_t type,
                                               unsigned int id);
void switch_handle_free(switch_handle_t handle);
switch_handle_type_t switch_handle_get_type(switch_handle_t handle);

#define SWITCH_HANDLE_VALID(handle, type) \
    ((handle >> HANDLE_TYPE_SHIFT) == type)

#define SWITCH_PORT_HANDLE_VALID(handle) \
    SWITCH_HANDLE_VALID(handle, SWITCH_HANDLE_TYPE_PORT)

#define SWITCH_INTERFACE_HANDLE_VALID(handle) \
    SWITCH_HANDLE_VALID(handle, SWITCH_HANDLE_TYPE_INTERFACE)

#define SWITCH_LAG_HANDLE_VALID(handle) \
    SWITCH_HANDLE_VALID(handle, SWITCH_HANDLE_TYPE_LAG)

#define SWITCH_VRF_HANDLE_VALID(handle) \
    SWITCH_HANDLE_VALID(handle, SWITCH_HANDLE_TYPE_VRF)

#define SWITCH_BD_HANDLE_VALID(handle) \
    SWITCH_HANDLE_VALID(handle, SWITCH_HANDLE_TYPE_BD)

#define SWITCH_TUNNEL_HANDLE_VALID(handle) \
    SWITCH_HANDLE_VALID(handle, SWITCH_HANDLE_TYPE_TUNNEL)

#define SWITCH_NHOP_HANDLE_VALID(handle) \
    SWITCH_HANDLE_VALID(handle, SWITCH_HANDLE_TYPE_NHOP)

#define SWITCH_NEIGHBOR_HANDLE_VALID(handle) \
    SWITCH_HANDLE_VALID(handle, SWITCH_HANDLE_TYPE_ARP)

#define SWITCH_RMAC_HANDLE_VALID(handle) \
    SWITCH_HANDLE_VALID(handle, SWITCH_HANDLE_TYPE_MY_MAC)

#define SWITCH_STP_HANDLE_VALID(handle) \
    SWITCH_HANDLE_VALID(handle, SWITCH_HANDLE_TYPE_STP)

#define SWITCH_MGID_HANDLE_VALID(handle) \
    SWITCH_HANDLE_VALID(handle, SWITCH_HANDLE_TYPE_MGID)

#define SWITCH_ACL_HANDLE_VALID(handle) \
    SWITCH_HANDLE_VALID(handle, SWITCH_HANDLE_TYPE_ACL)

#define SWITCH_ACE_HANDLE_VALID(handle) \
    SWITCH_HANDLE_VALID(handle, SWITCH_HANDLE_TYPE_ACE)

#define SWITCH_HOSTIF_GROUP_HANDLE_VALID(handle) \
    SWITCH_HANDLE_VALID(handle, SWITCH_HANDLE_TYPE_HOSTIF_GROUP)

#define SWITCH_HOSTIF_HANDLE_VALID(handle) \
    SWITCH_HANDLE_VALID(handle, SWITCH_HANDLE_TYPE_HOSTIF)

// Easy use macros
#define SWITCH_API_INVALID_HANDLE 0xFFFFFFFF
#define SWITCH_HW_INVALID_HANDLE 0xFFFFFFFF

#define _switch_handle_create(_type, _info, _judy, _init, _handle)      \
    _handle = switch_handle_allocate(_type);                            \
    if(_handle) {                                                       \
        _info *_i_info = (_info *)switch_malloc(sizeof(_info), 1);      \
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

#define _switch_handle_set_and_create(                                  \
        _type, _info, _judy, _init, _id, _handle)                       \
    _handle = switch_handle_set_and_allocate(_type, _id);               \
    if(_handle) {                                                       \
        _info *_i_info = (_info *)switch_malloc(sizeof(_info), 1);      \
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
