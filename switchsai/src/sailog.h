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

#ifndef _SAI_LOG_H
#define _SAI_LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

#include <sai.h>

void my_log(int level, sai_api_t api, char *fmt, ...);

#define SAI_LOG(level, api, fmt, arg ...) \
            do { \
                my_log(level, api, "[F:%s L:%d Func:%s] " fmt, \
                    __FILE__, __LINE__, __func__, ##arg); \
            } while(0);

#define SAI_LOG_ENTER(api)              \
    SAI_LOG(SAI_LOG_DEBUG, api, "Entering %s\n", __FUNCTION__)

#define SAI_LOG_EXIT(api)               \
    SAI_LOG(SAI_LOG_DEBUG, api, "Exiting %s\n", __FUNCTION__)

#endif // _SAI_LOG_H

