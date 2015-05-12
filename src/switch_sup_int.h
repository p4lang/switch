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
//  switch_sup_int.h
//  switch_api
//
//  Created on 7/28/14.
//  Copyright (c) 2014 bn. All rights reserved.
//

#ifndef _switch_sup_int_h_
#define _switch_sup_int_h_

#include "switchapi/switch_base_types.h"
#include "switchapi/switch_handle.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
    
typedef struct switch_sup_info_ {
    p4_pd_entry_hdl_t tx_entry;
    p4_pd_entry_hdl_t rx_entry;
} switch_sup_info_t;

/*
 * Internal API's
 */
int switch_sup_init();

#ifdef __cplusplus
}
#endif

#endif
