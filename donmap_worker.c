/* Copyright (c) 2016, Tejas Kokje. All rights reserved
 * Use of this source code is governed by a Simplified BSD
 * license that can be found in the LICENSE file.*/

#include "donmap.h"
/* This function is the starting of worker thread function
 * for doing TCP port scan using conect()*/
void *donmap_tcp_connect_worker(void *args)
{
    int sockfd, flags, n, error, working_port = 0;
    socklen_t len;
    struct timeval tval;
    struct addrinfo hints, *servinfo, *p;
    int rv, i;
    char port_str[6];
    fd_set wset;
    donmap_thread_cfg_t *thread_cfg;
    FD_ZERO(&wset);

    thread_cfg = (donmap_thread_cfg_t *) args;
    if (thread_cfg == NULL) {
		fprintf(stderr, "%s() Invalid argument\n", __FUNCTION__);
		return NULL;
    }

    /* Walk through all the ports assigned to this thread. 
     * thread_cfg->port will tell us which ports we should 
     * scan. thread_cfg->port + 1 is the first port to scan*/
    for (i = 1; i <= gbl_cfg.num_ports_per_thread; i++) {
		working_port = thread_cfg->port + i;

		if (working_port > NUM_PORTS
			|| working_port > gbl_cfg.end_port || thread_error) {
			break;
		}

        /*Resolve hostname first*/
		memset(&hints, 0, sizeof hints);
		if (gbl_cfg.use_ipv6) {
			hints.ai_family = AF_INET6;
		} else {
			hints.ai_family = AF_INET;
		}

		hints.ai_socktype = SOCK_STREAM;
		snprintf(port_str, 6, "%d", working_port);
		if ((rv = getaddrinfo(thread_cfg->hostname, port_str, &hints, &servinfo)) != 0) {
			pthread_mutex_lock(&thread_lock);
			if (!thread_error) {
				fprintf(stderr, "\nFailed to resolve or route %s\n", thread_cfg->hostname);
				fflush(stderr);
			}
			thread_error = 1;
			pthread_mutex_unlock(&thread_lock);
			return NULL;
		}

		// loop through all the results and connect to the first we can
		for (p = servinfo; p != NULL; p = p->ai_next) {
			if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
				pthread_mutex_lock(&thread_lock);
				if (!thread_error) {
					fprintf(stderr,
						"\nFailed to open socket for %s port %d - %s\n",
						thread_cfg->hostname, working_port, strerror(errno));
				}

				thread_error = 1;
				pthread_mutex_unlock(&thread_lock);
				return NULL;
			}

            /* Set socket to non blocking. We will use select() to catch response*/
			flags = fcntl(sockfd, F_GETFL, 0);
			fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
			if ((n = connect(sockfd, p->ai_addr, p->ai_addrlen)) < 0) {
				if (errno != EINPROGRESS) {
					close(sockfd);
					pthread_mutex_lock(&thread_lock);
					if (!thread_error) {
						fprintf(stderr,
							"\nFailed to connect for %s port %d - %s\n",
							thread_cfg->hostname, working_port, strerror(errno));
					}
					thread_error = 1;
					pthread_mutex_unlock(&thread_lock);
					return NULL;
				}
			}

			if (n == 0) {
                /* Connected immediately*/
				BITSET(port_map, working_port);
				BITSET(completed_port_map, working_port);
				break;
			}

			FD_ZERO(&wset);
			FD_SET(sockfd, &wset);
			break;
		}

		if (p) {
sel:
			tval.tv_sec = 0;
			tval.tv_usec = gbl_cfg.timeout;
			if ((n = select(sockfd + 1, NULL, &wset, NULL, &tval)) == 0) {
				errno = ETIMEDOUT;
				BITSET(completed_port_map, working_port);
				close(sockfd);
				continue;
			}
			if (errno == EINTR) {
				goto sel;
			}

			if (FD_ISSET(sockfd, &wset)) {
				len = sizeof(error);
				if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len)< 0) {
					close(sockfd);
					BITSET(completed_port_map, working_port);
					continue;
				} else {
					if (!error) {
                        /* Connected to remote port. Set the bit in port_map
                         * indicating success*/
						BITSET(port_map, working_port);
					}
				}

			} else {
				fprintf(stderr, "\nselect() error. sockfd is not set\n");
			}
		} else {
			pthread_mutex_lock(&thread_lock);
			if (!thread_error) {
			fprintf(stderr,
				"\nFailed to connect for %s port %d - %s\n",
				thread_cfg->hostname, working_port, strerror(errno));
			}
			thread_error = 1;
			pthread_mutex_unlock(&thread_lock);
			return NULL;
		}

		close(sockfd);
		BITSET(completed_port_map, working_port);
    }

    return NULL;
}

void *donmap_progress_worker(void *args)
{
    sleep(1);
    memset(out_buff, 32, 150);
    out_buff[0] = '\r';
    out_buff[1] = '[';
    out_buff[103] = ']';
    out_buff[108] = '\0';
    snprintf(out_buff + 104, 5, "%d%%", 0);
    fprintf(stdout, "%s", out_buff);
    fflush(stdout);
    char toggleChar = ' ';
    int prevPercent = 0, currPercent = 0;

    while (1) {
		int i, completedCount = 0;
		for (i = 1; i < NUM_PORTS; i++) {
			if (BITTEST(completed_port_map, i)) {
				completedCount++;
			}
		}
		currPercent = (int) ((completedCount * 100) / (gbl_cfg.end_port - gbl_cfg.start_port + 1));
		if (currPercent <= 100 && currPercent > prevPercent) {
			memset(out_buff + 2 + prevPercent, '#', currPercent - prevPercent);
			snprintf(out_buff + 104, 5, "%d%%", currPercent);
			fprintf(stdout, "%s", out_buff);
			fflush(stdout);
			prevPercent = currPercent;
		} else {
			out_buff[currPercent + 2] = toggleChar;
			fprintf(stdout, "%s", out_buff);
			fflush(stdout);
			toggleChar = (toggleChar == ' ' ? '#' : ' ');
		}
		sleep(1);
    }

    return NULL;
}
