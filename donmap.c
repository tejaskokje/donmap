/* Copyright (c) 2016, Tejas Kokje. All rights reserved
 * Use of this source code is governed by a Simplified BSD
 * license that can be found in the LICENSE file.*/

#include "donmap.h"

void print_usage(int print_header)
{
    char *usage =  "Copyright (c) 2016, Tejas Kokje\n"
                   "Usage: donmap [options]\nOPTIONS: \n"
                   "\t -? : Print this help string.\n"
                   "\t -6 : Use IPv6 for layer 3 communication (default is IPV4).\n"
                   "\t -f : First port to start the scan. Number should be between 1 and 65535.\n"
                   "\t -h : Print this help string.\n"
                   "\t -l : Last port to finish the scan. Number should be between 1 and 65535.\n"
                   "\t -n : Do not resolve port numbers to services in results.\n"
                   "\t -s : Scan all addresses in the subnet. Input should be in CIDR format.\n"
                   "\t      E.g. 192.168.1.0/24. This option cannot be used with -t option.\n"
 				   "\t -p : Number of threads that will run in parallel. Number should be between\n"
                   "\t      1 and 16 (default is 8).\n"
                   "\t -t : Target host to scan ports. This option cannot be used with -n option.\n"
                   "\t      If both -t and -n options are missing, localhost is scanned for open ports.\n"
                   "\t -w : Wait time in milliseconds before connection timeout. Number should be between\n"
                   "\t      1 and 10000 (default is 400)."
                   "\nEXAMPLES:\n\n"
                   "To scan www.google.com from TCP ports 20 to 100 with timeout value of 40 milliseconds \n"
                   "using 4 threads in parallel, use following command \n"
                   "\t donmap -w 40 -f 20 -l 100 -p 4 -t www.google.com\n\n"
                   "To scan 192.168.0.0/16 for all TCP ports with output only displaying numeric ports use \n"
                   "following command \n"
                   "\t donmap -s 192.168.0.0/16 -n \n\n"
                   "To scan www.facebook.com for TCP ports 20 to 4096 with IPv6 address and timeout value of \n"
                   "100 milliseoonds, use following command\n"
                   "\t donmap -6 -t www.facebook.com -f 20 -l 4096 -w 100 \n\n";
                   
    fprintf(stdout, "Definitely Outstanding Network Mapper (DO-nmap) version %s\n%s", DO_NMAP_VERSION, usage);
    
}

static void print_results()
{
    int i, total_ports;
    struct servent *srvInfo;
    /* If progress thread is running, mark the progress bar 
     * to 100%*/
    if (progress_tid) {
		memset(out_buff + 2, '#', 101);
		snprintf(out_buff + 104, 6, "%d%%\n", 100);
		fprintf(stdout, "%s", out_buff);
    }

    char header[100];
    
    /*Output global configuration fields first */
    total_ports = gbl_cfg.end_port - gbl_cfg.start_port + 1;
    fprintf(stdout, RESULT_FMT_STRING, gbl_cfg.hostname, (gbl_cfg.use_ipv6 ? "IPv6" : "IPv4"), gbl_cfg.start_port, 
            gbl_cfg.end_port, total_ports,(total_ports == 1 ? "port" : "ports"), (gbl_cfg.timeout/1000), 
            threads_started, gbl_cfg.num_threads, gbl_cfg.num_ports_per_thread);
    if (gbl_cfg.resolve_ports) {
        i = snprintf(header, 32, "OPEN PORT         SERVICE NAME\n");
        snprintf(header + i, 32, "----------        ------------\n");
    } else {
        i = snprintf(header, 14, "OPEN PORT  \n");
        snprintf(header + i, 14, "----------  \n");
    }

    fprintf(stdout, "%s", header);
 
    /* Now output discovered ports */
    for (i = 1; i < NUM_PORTS; i++) {
		if (BITTEST(port_map, i)) {
            if (gbl_cfg.resolve_ports) {
				srvInfo = getservbyport(htons(i), "tcp");
				if (srvInfo) {
				    fprintf(stdout, "%s/%-7d       %s\n",
					       "tcp", i, srvInfo->s_name);
				} else {
				    fprintf(stdout, "%s/%-7d       %s\n", "tcp", i, "unknown");
				}
            } else {
                fprintf(stdout, "%s/%-7d  \n", "tcp", i);
            }
		}
    }

    fflush(stdout);
}

/* This function parses input options and sets the flag in global configuration */
int donmap_parse_opt(int argc, char *argv[], donmap_global_cfg_t * gbl_cfg)
{
    if (!gbl_cfg) {
		fprintf(stderr, "%s() Invalid argument \"gbl_cfg\" to function call\n", __FUNCTION__);
		abort();
    }

    int option;
    char *e;

    while ((option = getopt(argc, argv, "6p:f:l:nw:s:t:?h")) != -1) {
		switch (option) {
		case 'p':
            if (gbl_cfg->thread_flag) {
                fprintf(stderr, "Invalid argument. Duplicate -p option\n");
                return -1;
            }

			e = NULL;
			gbl_cfg->num_threads = strtol(optarg, &e, 10);
			if (e != NULL && *e == (char) 0) {
				if (gbl_cfg->num_threads < 1 || gbl_cfg->num_threads > 16) {
					fprintf(stderr,
						"Invalid argument for option -p. Expected number between 1 and 16\n");
					return -1;
				}
			} else {
				fprintf(stderr,
					"Invalid argument for option -p. Expected number between 1 and 16\n");
				return -1;
			}
			gbl_cfg->thread_flag = 1;
			gbl_cfg->num_ports_per_thread = ((gbl_cfg->end_port - gbl_cfg->start_port + 1) / gbl_cfg->num_threads) + 1;
			break;
		case 'f':
            if (gbl_cfg->start_port_flag) {
                fprintf(stderr, "Invalid argument. Duplicate -f option\n");
                return -1;
            }

			e = NULL;
			gbl_cfg->start_port = strtol(optarg, &e, 10);
			if (e != NULL && *e == (char) 0) {
				if (gbl_cfg->start_port < 1 || gbl_cfg->start_port > 65535) {
					fprintf(stderr,
						"Invalid argument for option -f. Expected number between 1 and 65535\n");
					return -1;
				} else if (gbl_cfg->start_port > gbl_cfg->end_port) {
					fprintf(stderr,
						"Invalid argument for option -f. First port to scan cannot be greater than last port\n");
					return -1;
				}
			} else {
				fprintf(stderr,
					"Invalid argument for option -f. Expected number between 1 and 65535\n");
				return -1;
			}
            gbl_cfg->start_port_flag = 1;
			gbl_cfg->num_ports_per_thread = ((gbl_cfg->end_port - gbl_cfg->start_port + 1) / gbl_cfg->num_threads) + 1;
			break;
		case 'l':
            if (gbl_cfg->end_port_flag) {
                fprintf(stderr, "Invalid argument. Duplicate -l option\n");
                return -1;
            }
			e = NULL;
			gbl_cfg->end_port = strtol(optarg, &e, 10);
			if (e != NULL && *e == (char) 0) {
				if (gbl_cfg->end_port < 1 || gbl_cfg->end_port > 65535) {
					fprintf(stderr,
						"Invalid argument for option -l. Expected number between 1 and 65535\n");
					return -1;
				} else if (gbl_cfg->end_port < gbl_cfg->start_port) {
					fprintf(stderr,
						"Invalid argument for option -l. Last port to scan cannot be less than first port\n");
					return -1;
				}
			} else {
				fprintf(stderr,
					"Invalid argument for option -l. Expected number between 1 and 65535\n");
				return -1;
			}
			gbl_cfg->end_port_flag = 1;
			gbl_cfg->num_ports_per_thread = ((gbl_cfg->end_port - gbl_cfg->start_port + 1) / gbl_cfg->num_threads) + 1;
			break;

        case 'n':
            gbl_cfg->resolve_ports = 0;
            break;
		case 's':
			{
                if (gbl_cfg->net_flag) {
					fprintf(stderr, "Invalid argument. Duplicate -s option\n");
					return -1;
                }

				if (gbl_cfg->target_flag == 1) {
					fprintf(stderr, "Invalid argument. -s option cannot be used with -t\n");
					return -1;
				}
              
                if (gbl_cfg->use_ipv6) {
					fprintf(stderr, "Invalid argument. -s option cannot be used with -6\n");
					return -1;
                }
                
				int count = 0;
				gbl_cfg->net_flag = 1;
				char *delimit = "/";
				char *token;
				token = strtok(optarg, delimit);
				while (token != NULL) {
					if (count == 0) {
						if (!inet_pton(AF_INET, token, &gbl_cfg->net_addr.sin_addr)) {
							fprintf(stderr, "Invalid IPv4 address: %s\n", token);
							return -1;
						}
					} else if (count == 1) {
						e = NULL;
						gbl_cfg->mask = strtol(token, &e, 10);
						if (e != NULL && *e == (char) 0) {
							if (gbl_cfg->mask < 1 || gbl_cfg->mask > 30) {
							fprintf(stderr,
								"Invalid argument for option -s. Expected number between 1 and 30\n");
							return -1;
							}
						} else {
							fprintf(stderr,
								"Invalid argument for option -s. Expected number between 1 and 30\n");
							return -1;
						}

					} else {
						fprintf(stderr, "Invalid argument for -s option\n");
						return -1;
					}

					count++;
					token = strtok(NULL, delimit);
				}

                if (gbl_cfg->mask == 0) { 
                    fprintf(stderr, "Invalid argument for -s option. Expected input format network/subnet. E.g 192.168.1.0/24\n");
                    return -1;
                }

				gbl_cfg->mask = (0xFFFFFFFF << (32 - gbl_cfg->mask));
			}
           
			break;

		case 'w':
			if (gbl_cfg->timeout_flag) {
				fprintf(stderr, "Invalid argument. Duplicate -w option\n");
				return -1;
			}

			e = NULL;
			gbl_cfg->timeout = strtol(optarg, &e, 10);
			if (e != NULL && *e == (char) 0) {
                if (gbl_cfg->timeout < 1 || gbl_cfg->timeout > 10000) {
                    fprintf(stderr, "Invalid argument for -w option. Expected number between 1 and 10000\n");
                    return -1;
                }

				/* convert milliseconds to microseconds for use with timeval */
				gbl_cfg->timeout = gbl_cfg->timeout * 1000;
			} else {
				fprintf(stderr,
					"Invalid argument for option -p. Expected number between 1 and 16\n");
				return -1;
			}
			gbl_cfg->timeout_flag = 1;
			break;
		case 't':
			if (gbl_cfg->target_flag) {
				fprintf(stderr, "Invalid argument. Duplicate -t option\n");
				return -1;
			}

			if (gbl_cfg->net_flag == 1) {
				fprintf(stderr, "Invalid argument. -s option cannot be used with -t\n");
				return -1;
			}

			gbl_cfg->target_flag = 1;
			strncpy(gbl_cfg->hostname, optarg, 2048);
			break;

		case '6':
            if (gbl_cfg->net_flag) {
				fprintf(stderr, "Invalid argument. -6 option cannot be used with -s\n");
				return -1;
            }
     
            if (gbl_cfg->target_flag == 0) {
                /* Since no target (-t option) is given, default to ::1 for local IPv6 address */
                strncpy(gbl_cfg->hostname, "::1", 4);       
            }

			gbl_cfg->use_ipv6 = 1;
			break;
        case '?':
        case 'h':
            print_usage(1);
            return -1;
            break;
		default:
			print_usage(0);
			return -1;
		}
    }

    return 0;
}
static void donmap_cleanup()
{
    pthread_mutex_destroy(&thread_lock);

    /* Free up memory for threads */
    free(thread_cfg);
}

/* Signal handler for CTRL+C*/
void sig_int_handler(int sig)
{
    int i;
    signal(sig, SIG_IGN);
    if (!thread_error) {
        print_results();
    }

    /* Cancel all worker threads */
    for (i = 0; i < gbl_cfg.num_threads; i++) {
   	    pthread_cancel(threads[i]);
    }

    donmap_cleanup();
    exit(0);
}

int main(int argc, char *argv[])
{
    memset(port_map, 0, BITNSLOTS(NUM_PORTS));
    memset(completed_port_map, 0, BITNSLOTS(NUM_PORTS));
    int i, rc;
    void *status;
    struct tm *local;
    time_t start_time, end_time;
    double time_diff;
    char time_buf[35];
    uint32_t host;
    uint32_t num_host = 0;

    progress_tid = 0;
    pthread_mutex_init(&thread_lock, NULL);
    /* Install signal handler to catch ctrl+c */
    signal(SIGINT, sig_int_handler);
    /* Initialize default global configuration */
    donmap_global_cfg_init(&gbl_cfg);

    /* Parse input for options */
    rc = donmap_parse_opt(argc, argv, &gbl_cfg);
    if (rc) {
	    return rc;
    }

    /* Allocate memory for threads */
    donmap_thread_cfg_init(&thread_cfg, gbl_cfg.num_threads);

    /* Print current date/time */
    start_time = time(NULL);
    local = localtime(&start_time);
    i = snprintf(time_buf, 35, "%s", asctime(local));
    snprintf(time_buf + i - 1, 35, " %s", tzname[local->tm_isdst]);
    fprintf(stdout, "\nStarting DO-nmap version %s at %s\n", DO_NMAP_VERSION, time_buf);
    time(&start_time);

    if (gbl_cfg.net_flag) {
        /* -s network option given */
   	    num_host = ~gbl_cfg.mask - 1;
    } else {
	    /* hostname given */
	    num_host = 1;
    }

    /*Walk through all the hosts and scan each one of them*/
    for (host = 1; host <= num_host; host++) {
        threads_started = 0;
        thread_error = 0;
        memset(threads, 0, sizeof(pthread_t)*MAX_THREADS);

        /* Get the hostname and save it in global config. Hostname will be
         * updated at each iteration */
		if (gbl_cfg.net_flag) {
			struct sockaddr_in tmp = gbl_cfg.net_addr;
			tmp.sin_addr.s_addr = htonl((ntohl(gbl_cfg.net_addr.sin_addr.s_addr)
						 & gbl_cfg.mask) + host);
			inet_ntop(AF_INET, &tmp.sin_addr, gbl_cfg.hostname, INET_ADDRSTRLEN);
		}

		memset(port_map, 0, BITNSLOTS(NUM_PORTS));
		memset(completed_port_map, 0, BITNSLOTS(NUM_PORTS));
		fprintf(stdout, "\n======== Scanning for TCP ports in range %d - %d at %s ========\n", gbl_cfg.start_port, 
				gbl_cfg.end_port, gbl_cfg.hostname);
		for (i = 0; i < gbl_cfg.num_threads; i++) {
			thread_cfg[i].hostname = gbl_cfg.hostname;
			thread_cfg[i].port = i * gbl_cfg.num_ports_per_thread + (gbl_cfg.start_port - 1);
			if (thread_cfg[i].port + 1 > gbl_cfg.end_port) {
				/* We don't need more threads */
				break;
			}

			rc = pthread_create(&threads[i], NULL, gbl_cfg.thread_func, &thread_cfg[i]);
			if (rc) {
				fprintf(stderr, "ERROR: return code from pthread_create() is %d\n", rc);
				donmap_cleanup();
				return -1;
			}

			threads_started++;
		}

		/* Start a progress thread */
		rc = pthread_create(&progress_tid, NULL, donmap_progress_worker, NULL);
		if (rc) {
			fprintf(stderr, "ERROR: Cannot start progress thread. %d\n", rc);
			/* Dont bail out. Progress thread is optional */
		}

		for (i = 0; i < threads_started; i++) {
			pthread_join(threads[i], &status);
		}

		if (!thread_error) {
			print_results();
		}
		/* Kill progress thread */
		pthread_cancel(progress_tid);
    }

    if (!thread_error) {
		time(&end_time);
		time_diff = difftime(end_time, start_time);
		if (time_diff == 0) {
			fprintf(stdout, "\nScan of %d %s completed in less than a second\n", num_host, (num_host == 1 ? "host" : "hosts"));
		} else {
			fprintf(stdout, "\nScan of %d %s completed in %d %s\n", num_host, (num_host == 1 ? "host" : "hosts"),
                    (int) time_diff, ((int)time_diff == 1 ? "second" : "seconds"));
		}
    }

    fflush(stdout);
    donmap_cleanup();
    return 0;
}
