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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <getopt.h>
#include <assert.h>

#include <bmpd/switch/pd/pd.h>
#include <bm/pdfixed/pd_static.h>
#include <bm/pdfixed/thrift-src/pdfixed_rpc_server.h>
#include <bmpd/switch/thrift-src/pd_rpc_server.h>

char *pd_server_str = NULL;
char *of_controller_str = NULL;
int of_ipv6 = 0;

/**
 * The maximum number of ports to support:
 * @fixme should be runtime parameter
 */
#define PORT_COUNT 256
#define PD_SERVER_DEFAULT_PORT 9090

/**
 * Check an operation and return if there's an error.
 */
#define CHECK(op)                                                     \
  do {                                                                \
    int _rv;                                                          \
    if ((_rv = (op)) < 0) {                                           \
      fprintf(stderr, "%s: ERROR %d at %s:%d",                        \
              #op, _rv, __FILE__, __LINE__);                          \
      return _rv;                                                     \
    }                                                                 \
  } while (0)

#ifdef SWITCHLINK_ENABLE
extern int switchlink_init(void);
#endif /* SWITCHLINK_ENABLE */

#ifdef SWITCHAPI_ENABLE
extern int switch_api_init(int device, unsigned int num_ports);
extern int start_switch_api_rpc_server(void);
extern int start_switch_api_packet_driver(void);
#endif /* SWITCHAPI_ENABLE */

#ifdef SWITCHSAI_ENABLE
#define SWITCH_SAI_THRIFT_RPC_SERVER_PORT "9092"
extern int start_p4_sai_thrift_rpc_server(char * port);
#endif /* SWITCHSAI_ENABLE */

#ifdef OPENFLOW_ENABLE
extern void p4ofagent_init(bool ipv6, char *ip_ctl);
#endif

int
bmv2_model_init() {
  int rv=0;
  /* Start up the PD RPC server */
  void *pd_server_cookie;
  start_bfn_pd_rpc_server(&pd_server_cookie);
  add_to_rpc_server(pd_server_cookie);

  p4_pd_init();
  p4_pd_dc_init();
  p4_pd_dc_assign_device(0, "ipc:///tmp/bmv2-0-notifications.ipc", 10001);

  /* Start up the API RPC server */
#ifdef SWITCHAPI_ENABLE
  CHECK(switch_api_init(0, 256));
  CHECK(start_switch_api_rpc_server());
  CHECK(start_switch_api_packet_driver());
#endif /* SWITCHAPI_DISABLE */

#ifdef SWITCHSAI_ENABLE
  CHECK(start_p4_sai_thrift_rpc_server(SWITCH_SAI_THRIFT_RPC_SERVER_PORT));
#endif /*SWITCHSAI_ENABLE */

#ifdef SWITCHLINK_ENABLE
  CHECK(switchlink_init());
#endif /* SWITCHLINK_ENABLE */

#ifdef OPENFLOW_ENABLE
  p4ofagent_init(of_ipv6, of_controller_str);
#endif
  
  return rv;
}
