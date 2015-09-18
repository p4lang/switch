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

#include "switchapi/switch_handle.h"
#include "switchapi/switch_status.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    
static void *switch_handle_array;
    
int
switch_handle_type_init(switch_handle_type_t type, unsigned int size)
{
    switch_handle_info_t              *handle_info = NULL;
    switch_api_id_allocator           *allocator = NULL;
    void                              *p = NULL;

    handle_info = switch_malloc(sizeof(switch_handle_info_t), 1);
    if (!handle_info) {
        return SWITCH_STATUS_FAILURE;
    }
    allocator = switch_api_id_allocator_new (size, FALSE);
    if (!allocator) {
        switch_free(handle_info);
        return -1;
    }
    handle_info->type = type;
    handle_info->initial_size = size;
    handle_info->allocator = allocator;
    handle_info->num_in_use = 0;
    JLI(p, switch_handle_array, (unsigned int)type);
    if(p) {
       *(unsigned long *)p = (unsigned long)handle_info;
       return SWITCH_STATUS_SUCCESS;
    }
    switch_free(handle_info);
    return SWITCH_STATUS_FAILURE;
}
    
void
switch_handle_type_free(switch_handle_type_t type)
{
    switch_handle_info_t              *handle_info = NULL;
    void                              *p = NULL;
    int                                ret = 0;

    JLG(p, switch_handle_array, (unsigned int)type);
    if((handle_info = (switch_handle_info_t *) (*(unsigned long *)p))) {
        switch_api_id_allocator_destroy (handle_info->allocator);
        JLD(ret, switch_handle_array, (unsigned int)type);
        // assert(ret != 0);
        switch_free(handle_info);
    }
}
    
switch_handle_t
switch_handle_allocate(switch_handle_type_t type)
{
    switch_handle_info_t              *handle_info = NULL;
    void                              *p = NULL;

    JLG(p, switch_handle_array, (unsigned int)type);
    if((handle_info = (switch_handle_info_t *) (*(unsigned long *)p))) {
        unsigned int id = switch_api_id_allocator_allocate (handle_info->allocator);
        handle_info->num_in_use++;
        return ((type << HANDLE_TYPE_SHIFT) | id);
    }
    return SWITCH_API_INVALID_HANDLE;
}

switch_handle_t
switch_handle_set_and_allocate(switch_handle_t type, unsigned int id)
{
    switch_handle_info_t              *handle_info = NULL;
    void                              *p = NULL;

    JLG(p, switch_handle_array, (unsigned int)type);
    if((handle_info = (switch_handle_info_t *) (*(unsigned long *)p))) {
        switch_api_id_allocator_set(handle_info->allocator, id);
        handle_info->num_in_use++;
        return ((type << HANDLE_TYPE_SHIFT) | id);
    }
    return SWITCH_API_INVALID_HANDLE;
}
    
void
switch_handle_free(switch_handle_t handle)
{
    switch_handle_type_t               type = SWITCH_HANDLE_TYPE_NONE;
    switch_handle_info_t              *handle_info = NULL;
    void                              *p = NULL;

    type = (handle & 0xF8000000) >> HANDLE_TYPE_SHIFT;
    JLG(p, switch_handle_array, (unsigned int)type);
    if((handle_info = (switch_handle_info_t *) (*(unsigned long *)p))) {
        switch_api_id_allocator_release(handle_info->allocator, handle & 0x00FFFFFF);
        handle_info->num_in_use--;
    }
}
    
switch_handle_type_t
switch_handle_get_type(switch_handle_t handle)
{
    switch_handle_type_t type = (handle & 0xF8000000) >> HANDLE_TYPE_SHIFT;
    return type;
}
    
#ifdef SWITCH_HANDLE_TEST
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int _handle_main (int argc, char **argv)
{
    switch_handle_type_init(SWITCH_HANDLE_TYPE_PORT, 10);
    switch_handle_t id = switch_handle_allocate(SWITCH_HANDLE_TYPE_PORT);
    printf("id = 0x%lx\n", id);
    switch_handle_free(id);
    switch_handle_type_free(SWITCH_HANDLE_TYPE_PORT);
    return 0;
}
#endif
    
#ifdef __cplusplus
}
#endif
