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

#include "switchapi/switch_id.h"
#include <string.h>

// #define SWITCH_ID_ALLOCATOR_TEST 1

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

switch_api_id_allocator *
switch_api_id_allocator_new(unsigned int initial_size, bool zero_based)
{
    switch_api_id_allocator *allocator = switch_malloc(sizeof(switch_api_id_allocator), 1);
    allocator->n_words = initial_size;
    allocator->data = switch_malloc(sizeof(uint32_t), initial_size);
    allocator->zero_based = zero_based;
    if (allocator->data) {
        memset(allocator->data, 0x0, initial_size*sizeof(uint32_t));
    }
    return allocator;
}

void
switch_api_id_allocator_destroy(switch_api_id_allocator *allocator)
{
    switch_free(allocator->data);
    switch_free(allocator);
}

static inline int
_fit_width( uint32_t val, unsigned width)
{
    unsigned                            offset = 32;
    uint32_t                            mask = 0;
    uint32_t                            b = 0;

    while(offset >= width)
    {
        mask = (((uint32_t)1 << width) - 1) << (offset - width);
        b = val & mask;
        if (!b)
            return offset;
        offset = __builtin_ctz(b);
    }
    return -1;
}

unsigned int
switch_api_id_allocator_allocate_contiguous (switch_api_id_allocator *allocator, uint8_t count)
{
    unsigned int i;
    for (i = 0; i < allocator->n_words; i++)
    {
        if (allocator->data[i] != 0xFFFFFFFF)
        {
            unsigned pos=-1;
            if ((pos=_fit_width(allocator->data[i], count)) > 0) {
                // set the bitmap to 1s
                allocator->data[i] |= (0xFFFFFFFF << (pos - count)) & 0xFFFFFFFF;
                return 32 * i + (32 - pos) +
                       (allocator->zero_based ? 0 : 1);
            }
        }
    }
    uint32_t n_words = allocator->n_words;
    allocator->data = switch_realloc(allocator->data, n_words * 2 *sizeof(uint32_t));
    memset (&allocator->data[n_words], 0x0, n_words * sizeof (uint32_t));
    allocator->n_words = n_words * 2;
    allocator->data[n_words] |= (0xFFFFFFFF << (32 - count)) & 0xFFFFFFFF;
    return 32 * n_words + (allocator->zero_based ? 0 : 1);
}

unsigned int
switch_api_id_allocator_allocate(switch_api_id_allocator *allocator)
{
    return switch_api_id_allocator_allocate_contiguous(allocator, 1);
}

void
switch_api_id_allocator_release(switch_api_id_allocator *allocator, unsigned int id)
{
    id = id > 0 ? id - 1 : 0;
    allocator->data[id >> 5] &= ~(1 << (31 - id));
}

/**
 * Set an allocated id
 * @param allocator allocator created with create
 * @param id id to set
 */
void
switch_api_id_allocator_set(switch_api_id_allocator *allocator, unsigned int id)
{
    //assert (allocator != NULL);
    if (allocator->zero_based != true)
    {
    /* For non-zero based allocator, an id of 0 is forbidden */
        //assert(id > 0);
        id = id - 1;
    }
    //assert((id>>5) < allocator->n_words);
    allocator->data[id >> 5] |= (1 << (31 - id));
}

/**
* Checks if an id is allocated or not
* @param allocator allocator created with create
* @param id id to check
*/
int
switch_api_id_allocator_is_set(switch_api_id_allocator *allocator, unsigned int id)
{
    //assert (allocator != NULL);
    if (allocator->zero_based != true)
    {
        //assert(id > 0);
        id = id - 1;
    }
    //assert((id>>5) < allocator->n_words);
    return((allocator->data[id>>5] & (1 << (31 -id))) ? 1:0);
}


#ifdef SWITCH_ID_ALLOCATOR_TEST
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#define MAX_ID_TEST (16*1024)
#define INITIAL_WORDS 4

int id_main (int argc, char **argv)
{
    unsigned int i;
    unsigned int iter;
    switch_api_id_allocator *allocator = switch_api_id_allocator_new (INITIAL_WORDS, FALSE);

    for(i=0;i<40;i++)
        switch_api_id_allocator_allocate(allocator);

    printf("words are 0x%x, 0x%x\n", (uint32_t)allocator->data[0], (uint32_t)allocator->data[1]);

    for(i=0;i<40;i++)
        switch_api_id_allocator_release(allocator, i+1);


    for (i = 0; i < MAX_ID_TEST; i++)
    {
        unsigned int id = switch_api_id_allocator_allocate (allocator);
        assert (id == i+1);
    }

    for (i = 0; i < MAX_ID_TEST; i++)
        switch_api_id_allocator_release (allocator, i);

    for (iter = 0; iter < MAX_ID_TEST; iter++)
    {
        for (i = 0; i < 1000; i++)
            switch_api_id_allocator_allocate (allocator);

        for (i = 0; i < 1000; i++)
            switch_api_id_allocator_release (allocator, i);
    }

#define NUM_BLOCKS 20
#define BLOCK_SIZE 8
    for(i=0;i<NUM_BLOCKS;i++) {
        unsigned int id = switch_api_id_allocator_allocate_contiguous(allocator, BLOCK_SIZE);
        printf("id = %d 0x%x\n", id, (uint32_t)allocator->data[i/4]);
    }
    for(i=1;i<=NUM_BLOCKS*BLOCK_SIZE;i++) {
        switch_api_id_allocator_release(allocator, i);
    }

    switch_api_id_allocator_destroy (allocator);
    return 0;
}

#endif

#ifdef __cplusplus
}
#endif
