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
#ifndef _SWITCH_LOG_INT_H_
#define _SWITCH_LOG_INT_H_

#include "p4features.h"
#include <switchapi/switch_status.h>
#include <switchapi/switch_log.h>

void switch_log_init();

extern switch_api_log_fn_t *switch_api_client_log_fn;

#define SWITCH_API_ERROR(...)   \
  if (switch_api_client_log_fn) \
    switch_api_client_log_fn(SWITCH_API_LOG_ERROR, __VA_ARGS__);

#define SWITCH_API_WARN(...)    \
  if (switch_api_client_log_fn) \
    switch_api_client_log_fn(SWITCH_API_LOG_WARN, __VA_ARGS__);

#define SWITCH_API_INFO(...)    \
  if (switch_api_client_log_fn) \
    switch_api_client_log_fn(SWITCH_API_LOG_INFO, __VA_ARGS__);

#define SWITCH_API_VERBOSE(...) \
  if (switch_api_client_log_fn) \
    switch_api_client_log_fn(SWITCH_API_LOG_VERBOSE, __VA_ARGS__);

#define SWITCH_API_TRACE(...)   \
  if (switch_api_client_log_fn) \
    switch_api_client_log_fn(SWITCH_API_LOG_TRACE, __VA_ARGS__);

char *switch_print_error(switch_status_t status);

#endif /*_SWITCH_LOG_INT_H_ */
