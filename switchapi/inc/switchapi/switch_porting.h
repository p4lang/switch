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

/**************************************************************************//**
 *
 * @file
 * @brief Switch Porting Macros.
 *
 * @addtogroup switch-porting
 * @{
 *
 *****************************************************************************/
#ifndef __SWITCH_PORTING_H__
#define __SWITCH_PORTING_H__


/* <auto.start.portingmacro(ALL).define> */
#if SWITCH_CONFIG_PORTING_INCLUDE_STDLIB_HEADERS == 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <memory.h>
#endif

#ifndef SWITCH_MALLOC
    #if defined(GLOBAL_MALLOC)
        #define SWITCH_MALLOC GLOBAL_MALLOC
    #elif SWITCH_CONFIG_PORTING_STDLIB == 1
        #define SWITCH_MALLOC malloc
    #else
        #error The macro SWITCH_MALLOC is required but cannot be defined.
    #endif
#endif

#ifndef SWITCH_FREE
    #if defined(GLOBAL_FREE)
        #define SWITCH_FREE GLOBAL_FREE
    #elif SWITCH_CONFIG_PORTING_STDLIB == 1
        #define SWITCH_FREE free
    #else
        #error The macro SWITCH_FREE is required but cannot be defined.
    #endif
#endif

#ifndef SWITCH_MEMSET
    #if defined(GLOBAL_MEMSET)
        #define SWITCH_MEMSET GLOBAL_MEMSET
    #elif SWITCH_CONFIG_PORTING_STDLIB == 1
        #define SWITCH_MEMSET memset
    #else
        #error The macro SWITCH_MEMSET is required but cannot be defined.
    #endif
#endif

#ifndef SWITCH_MEMCPY
    #if defined(GLOBAL_MEMCPY)
        #define SWITCH_MEMCPY GLOBAL_MEMCPY
    #elif SWITCH_CONFIG_PORTING_STDLIB == 1
        #define SWITCH_MEMCPY memcpy
    #else
        #error The macro SWITCH_MEMCPY is required but cannot be defined.
    #endif
#endif

#ifndef SWITCH_STRNCPY
    #if defined(GLOBAL_STRNCPY)
        #define SWITCH_STRNCPY GLOBAL_STRNCPY
    #elif SWITCH_CONFIG_PORTING_STDLIB == 1
        #define SWITCH_STRNCPY strncpy
    #else
        #error The macro SWITCH_STRNCPY is required but cannot be defined.
    #endif
#endif

#ifndef SWITCH_VSNPRINTF
    #if defined(GLOBAL_VSNPRINTF)
        #define SWITCH_VSNPRINTF GLOBAL_VSNPRINTF
    #elif SWITCH_CONFIG_PORTING_STDLIB == 1
        #define SWITCH_VSNPRINTF vsnprintf
    #else
        #error The macro SWITCH_VSNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef SWITCH_SNPRINTF
    #if defined(GLOBAL_SNPRINTF)
        #define SWITCH_SNPRINTF GLOBAL_SNPRINTF
    #elif SWITCH_CONFIG_PORTING_STDLIB == 1
        #define SWITCH_SNPRINTF snprintf
    #else
        #error The macro SWITCH_SNPRINTF is required but cannot be defined.
    #endif
#endif

#ifndef SWITCH_STRLEN
    #if defined(GLOBAL_STRLEN)
        #define SWITCH_STRLEN GLOBAL_STRLEN
    #elif SWITCH_CONFIG_PORTING_STDLIB == 1
        #define SWITCH_STRLEN strlen
    #else
        #error The macro SWITCH_STRLEN is required but cannot be defined.
    #endif
#endif

/* <auto.end.portingmacro(ALL).define> */


#endif /* __SWITCH_PORTING_H__ */
/* @} */
