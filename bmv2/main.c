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

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <stdio.h>

#include <getopt.h>
#include <assert.h>

extern char *pd_server_str;
extern char *of_controller_str;
extern int of_ipv6;

extern int bmv2_model_init();

static void
parse_options(int argc, char **argv)
{
  while (1) {
    int option_index = 0;
    /* Options without short equivalents */
    enum long_opts {
      OPT_START = 256,
      OPT_PDSERVER,
      OPT_OFIP,
      OPT_OFIPV6,
    };
    static struct option long_options[] = {
      {"help", no_argument, 0, 'h' },
      {"pd-server", required_argument, 0, OPT_PDSERVER },
      {"of-ip", required_argument, 0, OPT_OFIP },
      {"of-ipv6", no_argument, 0, OPT_OFIPV6 },
      {0, 0, 0, 0 }
    };
    int c = getopt_long(argc, argv, "h",
                        long_options, &option_index);
    if (c == -1) {
      break;
    }
    switch (c) {
      case OPT_PDSERVER:
        pd_server_str = strdup(optarg);
        break;
      case OPT_OFIP:
        of_controller_str = strdup(optarg);
        break;
      case OPT_OFIPV6:
        of_ipv6 = 1;
      case 'h':
      case '?':
        printf("Drivers! \n");
        printf("Usage: drivers [OPTION]...\n");
        printf("\n");
        printf(" --pd-server=IP:PORT Listen for PD RPC calls\n");
        printf(" -h,--help Display this help message and exit\n");
        exit(c == 'h' ? 0 : 1);
        break;
    }
  }
}

int
main(int argc, char* argv[])
{
  int rv = 0;

  parse_options(argc, argv);

  bmv2_model_init();

  while (1) pause();

  return rv;
}
