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

#include "switchapi/switch_utils.h"
#include "switch_ver.h"

#define SWITCH_L3_HASH_TABLE_SIZE (64*1024)

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

uint32_t MurmurHash2 ( const void * key, size_t len, uint32_t seed )
{
    // 'm' and 'r' are mixing constants generated offline.
    // They're not really 'magic', they just happen to work well.

#define m 0x5bd1e995
#define r 24

    // Initialize the hash to a 'random' value
    uint32_t h = seed ^ (unsigned int)len;

    // Mix 4 bytes at a time into the hash

    const unsigned char * data = (const unsigned char *)key;

    while(len >= 4)
    {
        uint32_t k = *(uint32_t *)data;

        k *= m;
        k ^= k >> r;
        k *= m;
        h *= m;
        h ^= k;

        data += 4;
        len -= 4;
    }

    // Handle the last few bytes of the input array

    switch(len)
    {
        case 3: h ^= data[2] << 16;
        case 2: h ^= data[1] << 8;
        case 1: h ^= data[0];
                h *= m;
    };

    // Do a few final mixes of the hash to ensure the last few
    // bytes are well-incorporated.

    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;

    return h;
}

const char *
switch_get_version(void)
{
    return SWITCH_VER;
}

const char *
switch_get_internal_version(void)
{
    return SWITCH_INTERNAL_VER;
}

#ifdef __cplusplus
}
#endif
