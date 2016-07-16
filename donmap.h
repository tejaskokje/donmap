/* Copyright (c) 2016, Tejas Kokje. All rights reserved
 * Use of this source code is governed by a Simplified BSD
 * license that can be found in the LICENSE file.*/

#ifndef DONMAP_H_INCLUDED
#define DONMAP_H_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <math.h>

#define DO_NMAP_VERSION "0.7"
/*BITSET macros. Credit http://c-faq.com/misc/bitsets.html */
#define BITMASK(b) (1 << ((b) % CHAR_BIT))
#define BITSLOT(b) ((b) / CHAR_BIT)
#define BITSET(a, b) ((a)[BITSLOT(b)] |= BITMASK(b))
#define BITCLEAR(a, b) ((a)[BITSLOT(b)] &= ~BITMASK(b))
#define BITTEST(a, b) ((a)[BITSLOT(b)] & BITMASK(b))
#define BITNSLOTS(nb) ((nb + CHAR_BIT - 1) / CHAR_BIT)

/* Global Constants*/
#define NUM_PORTS 65536
#define MAX_HOSTS 16
#define MAX_THREADS 16

#define RESULT_FMT_STRING "Host                           : %s\n"\
                          "Network Address Type           : %s\n"\
                          "Range of ports scanned         : %d - %d (%d total %s)\n"\
                          "Port timeout for this scan     : %d milliseconds\n"\
                          "Number of threads used         : %d (max allowed %d)\n"\
						  "Max number of ports per thread : %d \n"

char out_buff[150];
pthread_mutex_t thread_lock;
uint8_t thread_error;
uint8_t threads_started;
pthread_t threads[MAX_THREADS], progress_tid;
void *donmap_tcp_connect_worker(void *args);
void *donmap_progress_worker(void *args);
/* Global configuration for each donmap invocation */
typedef struct donmap_global_cfg_ {
    uint32_t timeout;		//timeout in microseconds
    uint8_t num_threads;
    uint8_t use_ipv6:1, net_flag:1, 
            target_flag:1, resolve_ports:1, thread_flag:1, 
             start_port_flag:1, end_port_flag:1, timeout_flag:1;
    uint16_t num_ports_per_thread;
    uint16_t start_port;
    uint16_t end_port;
    char hostname[2048];
    struct sockaddr_in net_addr;
    uint32_t mask;
    void *(*thread_func) (void *);	//worker function pointer
} donmap_global_cfg_t;

/* Thread specific configuration for each thread */
typedef struct donmap_thread_cfg_ {
    char *hostname;
    uint16_t port;
} donmap_thread_cfg_t;

static inline void donmap_global_cfg_init(donmap_global_cfg_t * global_cfg)
{
    if (!global_cfg)
	    return;
    global_cfg->timeout = 400000;	//400 milliseconds default
    global_cfg->num_threads = 16;
    global_cfg->use_ipv6 = 0;
    global_cfg->net_flag = 0;
    global_cfg->target_flag = 0;
    global_cfg->resolve_ports = 1;
    global_cfg->thread_flag = 0;
    global_cfg->start_port_flag = 0;
    global_cfg->end_port_flag = 0;
    global_cfg->timeout_flag = 0;
    global_cfg->num_ports_per_thread = NUM_PORTS / global_cfg->num_threads;
    global_cfg->start_port = 1;
    global_cfg->end_port = 65535;
    strncpy(global_cfg->hostname, "localhost", 10);
    global_cfg->thread_func = donmap_tcp_connect_worker;
}

static inline void donmap_thread_cfg_init(donmap_thread_cfg_t ** thread_cfg, int num_threads)
{
    if (!thread_cfg) {
		fprintf(stderr, "%s() invalid argument \"thread_cfg\"\n", __FUNCTION__);
		abort();
    }

    *thread_cfg = (donmap_thread_cfg_t *) malloc(num_threads * sizeof(donmap_thread_cfg_t));
    if (!*thread_cfg) {
		fprintf(stderr, "%s() malloc failure\n", __FUNCTION__);
		abort();
    }
}

char port_map[BITNSLOTS(NUM_PORTS)];
char completed_port_map[BITNSLOTS(NUM_PORTS)];
donmap_global_cfg_t gbl_cfg;
donmap_thread_cfg_t *thread_cfg;
#endif
