/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 * Copyright Pytilia Ltd Belfast
 */

#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <math.h>
#include <time.h>

#include "plugin.h"

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 1000
#define MAXBUFLEN 500

#define SRC_PORT_1 "4000"
#define SRC_PORT_2 "4001"
#define DST_PORT_1 "5000"
#define DST_PORT_2 "5001"


static struct {
    int process_type;
    int bounds_error;
    int permissions_error;
    int print;
} app_opts;

struct addrinfo *servinfo, *p1, *p2;

typedef uint64_t tsc_t;
static int tsc_dynfield_offset = -1;

static const char short_opts[] =
    "n"    /* No packet processing, only read to and clear buffers */
    "s"    /* Use single CHERI secured process */
    "i"    /* Use IPC model */
    "x"    /* Raise capability bounds error */
    "y"    /* Raise capability permissions error */
    "q"    /* Run in quiet mode */
    "v"    /* Run in verbose mode */
    ;

static const char usage[] =
    "%s EAL_ARGS -- [-s Single Process] [-i Inter Process] [-x Bounds Error]"
    "[-y Permissions Error] \n";

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
    },
};

/*
 * Get the current time in microseconds
 */
static long long
get_current_time(void) {
    struct timeval tv;

    gettimeofday(&tv, NULL);

    return (((long long)tv.tv_sec)*1000000)+(tv.tv_usec);
}

/*
 * Initialises a given port using global settings and with the rx buffers
 * coming from the mbuf_pool passed as parameter
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_rxconf rxconf;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n",
                port, strerror(-retval));

        return retval;
    }

    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |=
            DEV_TX_OFFLOAD_MBUF_FAST_FREE;

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    rxconf = dev_info.default_rxconf;

    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
            rte_eth_dev_socket_id(port), &rxconf, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }

    retval  = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    struct rte_ether_addr addr;

    retval = rte_eth_macaddr_get(port, &addr);
    if (retval < 0) {
        printf("Failed to get MAC address on port %u: %s\n",
            port, rte_strerror(-retval));
        return retval;
    }

    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0)
        return retval;

    return 0;
}

/*
 * Create a network socket 
 */
static int
create_socket(const char *port, struct addrinfo **p, int do_bind) {
    int sockfd;
    struct addrinfo hints, *q;
    int rv;

    // Create a hints struct
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_DGRAM;

    if ((rv = getaddrinfo("localhost", port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // loop through all the results and make a socket
    for(q = servinfo; q != NULL; q = q->ai_next) {
        if ((sockfd = socket(q->ai_family, q->ai_socktype,
                q->ai_protocol)) == -1) {
            perror("Error creating socket");
            continue;
        }

        if (do_bind) {
            if (bind(sockfd, q->ai_addr, q->ai_addrlen) == -1) {
                close(sockfd);
                perror("Error binding");
                continue;
            }        
        }
        break;
    }

    if (q == NULL) {
        fprintf(stderr, "Failed to create socket!\n");
        return -1;
    }

    *p = q;

    return sockfd;
}

/*
 * Main thread that does the work, reading from INPUT_PORT
 * and writing to OUTPUT_PORT
 */
static void
lcore_main(void)
{
    uint16_t port;
    int sockfd1, sockfd2;

    RTE_ETH_FOREACH_DEV(port)
        if (rte_eth_dev_socket_id(port) > 0 &&
                rte_eth_dev_socket_id(port) != (int)rte_socket_id())
            printf("WARNING, port %u is on remote NUMA node to polling thread."
                    "\n\tPerformance will not be optimal.\n", port);

    if (app_opts.print)
        printf("\nCore %u forwarding packets.\n", rte_lcore_id());

    // Create sockets
    if (app_opts.process_type == 2) { 
        if ((sockfd1 = create_socket(DST_PORT_1, &p1, 0)) < 0) {
            printf("Error creating socket 1!\n");
            return;
        }

        if ((sockfd2 = create_socket(DST_PORT_2, &p2, 0)) < 0) {
            printf("Error creating socket 2!\n");
            return;
        }
    }

    // Loop through all of the packets received
    int loop;
    uint64_t start, stop, total_time;
    start = get_current_time();
    for (loop = 1; loop;) {
        RTE_ETH_FOREACH_DEV(port) {
            struct rte_mbuf *bufs[BURST_SIZE];
            const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
            int i;

            // Stop looping once no packets remain
            if (unlikely(!nb_rx)) {
                if (app_opts.print)
                    printf("Received all packets successfully!\n");
                loop = 0;
                break;
            }

            if (app_opts.print)
                printf("Got %d packets\n", nb_rx);

            // Iterate through each packet received
            for (i = 0; i < nb_rx; i++) {
                size_t read_len = 0;
                char *c = NULL;
                unsigned int j, k;

                if (app_opts.process_type == 1) {
                    struct rte_mbuf current_buf = *bufs[i];
                    current_buf.buf_addr = cheri_setbounds(current_buf.buf_addr,
                            current_buf.data_off + current_buf.data_len);
                    current_buf.buf_addr = cheri_andperm(current_buf.buf_addr, ~CHERI_PERM_STORE);

                    read_len = rte_pktmbuf_pkt_len(&current_buf);
                    c = current_buf.buf_addr;

                    if (app_opts.print) {
                        printf("\nBuffer %d: Address %p, Length %lu\n",
                                i,
                                &current_buf,
                                read_len);
                        printf("Capability: Permissions 0x%lX, Address %p, Length %lu\n",
                                cheri_getperm(current_buf.buf_addr),
                                current_buf.buf_addr,
                                cheri_getlen(current_buf.buf_addr));
                    }

                    // Raise a permissions error
                    if (app_opts.permissions_error) {
                        printf("Attempting to write to read-only permissions.\n");
                        *c = 0xFF; 
                    }

                    // Raise a bounds error
                    if (app_opts.bounds_error) {
                        c = current_buf.buf_addr;
                        printf("Attempting to read beyond capability bounds.\n");
                        read_len++;
                    }

                    if (app_opts.print == 2 || app_opts.bounds_error) {
                        for (j = 0; j < ceil((double) read_len / 16.0); j++) {
                            for (k = 0; k < 16; k++) {
                                if (j*16+k < read_len) {
                                    printf("%02X ", c[current_buf.data_off + j*16+k]);
                                } else {
                                    printf("   ");
                                }
                            }
                            printf("| ");
                            for (k = 0; k < 16; k++) {
                                if (j*16+k < read_len) {
                                    printf("%c", c[current_buf.data_off + j*16+k]);
                                }
                            }
                            printf("\n");
                        }
                    }
                } else if (app_opts.process_type == 2) {
                    read_len =  rte_pktmbuf_pkt_len(bufs[i]);
                    c = bufs[i]->buf_addr;

                    if (app_opts.print) {
                        printf("\nBuffer %d: Address %p, Length %lu\n",
                                i, &bufs[i]->buf_addr, read_len);
                        printf("Capability: Permissions 0x%lX, Address %p, Length %lu\n",
                                cheri_getperm(bufs[i]->buf_addr),
                                bufs[i]->buf_addr,
                                cheri_getlen(bufs[i]->buf_addr));
                    }

                    if (app_opts.print == 2) {
                        for (j = 0; j < ceil((double) read_len / 16.0); j++) {
                            for (k = 0; k < 16; k++) {
                                if (j*16+k < read_len) {
                                    printf("%02X ", c[bufs[i]->data_off + j*16+k]);
                                } else {
                                    printf("   ");
                                }
                            }
                            printf("| ");
                            for (k = 0; k < 16; k++) {
                                if (j*16+k < read_len) {
                                    printf("%c", c[bufs[i]->data_off + j*16+k]);
                                }
                            }
                            printf("\n");
                        }
                    }
                }

                if (app_opts.process_type < 3) {
                    int consumer_id = c[bufs[i]->data_off] - 160;
                    if (app_opts.print)
                        printf("Updating consumer %i.\n", consumer_id);

                    if (app_opts.process_type == 1) {
                        plugin_consumer_interaction(consumer_id);
                    } else if (app_opts.process_type == 2) {
                        int numbytes;
                        if (!consumer_id) {
                            if ((numbytes = sendto(sockfd1, &c[bufs[i]->data_off], read_len,
                                    0, p1->ai_addr, p1->ai_addrlen)) == -1) {
                                perror("Error with sendto command");
                                exit(1);
                            }
                        } else {
                            if ((numbytes = sendto(sockfd2, &c[bufs[i]->data_off], read_len,
                                    0, p2->ai_addr, p2->ai_addrlen)) == -1) {
                                perror("Error with sendto command");
                                exit(1);
                            }
                        }

                        if (app_opts.print)
                            printf("Sent %d bytes to consumer.\n", numbytes);
                    }
                }
            }

            if (nb_rx) {
                uint16_t buf;
                for (buf = 0; buf < nb_rx; buf++)
                    rte_pktmbuf_free(bufs[buf]);
            }
        }
    }
    stop = get_current_time();
    total_time = stop - start;
    printf("Total packet processing time (us): %lu\n", total_time);

    unsigned long counters[2];
    if (app_opts.process_type == 1) {
        counters[0] = plugin_get_consumer_counter(1);
        counters[1] = plugin_get_consumer_counter(2);
    } else if (app_opts.process_type == 2) {
        int numbytes;
        const char *msg = "FINISHED";
        struct sockaddr_storage their_addr;
        socklen_t addr_len;
        char buf[MAXBUFLEN];

        if (app_opts.print)
            printf("Closing consumer 1.\n");
        if ((numbytes = sendto(sockfd1, msg, strlen(msg),
                0, p1->ai_addr, p1->ai_addrlen)) == -1) {
            perror("Error with sendto command");
            exit(1);
        }
        if (app_opts.print)
            printf("Sent %d bytes to consumer 1.\n", numbytes);

        if ((sockfd1 = create_socket(SRC_PORT_1, &p1, 1)) < 0) {
            printf("Error creating socket 1!\n");
            return;
        }

        if (app_opts.print)
            printf("Waiting for packet...\n");
        addr_len = sizeof their_addr;
        if ((numbytes = recvfrom(sockfd1, buf, MAXBUFLEN-1 , 0,
                (struct sockaddr *)&their_addr, &addr_len)) == -1) {
            perror("recvfrom");
            exit(1);
        }

        buf[numbytes] = '\0';
        counters[0] = atoi(buf);

        if (app_opts.print)
            printf("Closing consumer 2.\n");
        if ((numbytes = sendto(sockfd2, msg, strlen(msg),
                0, p2->ai_addr, p2->ai_addrlen)) == -1) {
            perror("Error with sendto command");
            exit(1);
        }
        if (app_opts.print)
            printf("Sent %d bytes to consumer 2.\n", numbytes);

        if ((sockfd2 = create_socket(SRC_PORT_2, &p2, 1)) < 0) {
            printf("Error creating socket 2!\n");
            return;
        }

        if (app_opts.print)
            printf("Waiting for packet...\n");
        addr_len = sizeof their_addr;
        if ((numbytes = recvfrom(sockfd2, buf, MAXBUFLEN-1 , 0,
                (struct sockaddr *)&their_addr, &addr_len)) == -1) {
            perror("recvfrom");
            exit(1);
        }

        buf[numbytes] = '\0';
        counters[1] = atoi(buf);

        freeaddrinfo(servinfo);
    } else if (app_opts.process_type == 3) {
        counters[0] = plugin_get_consumer_counter(1);
        counters[1] = plugin_get_consumer_counter(2);
    }

    printf("Consumer 1: %lu\n", counters[0]);
    printf("Consumer 2: %lu\n", counters[1]);

    return;
}

/* Main function, does initialisation and calls the per-lcore functions */
int
main(int argc, char *argv[])
{
    struct rte_mempool *mbuf_pool;
    uint16_t nb_ports, portid;
    struct option lgopts[] = {
        { NULL,         no_argument,    0,       0 },
        { "NoProc",     no_argument,    NULL,    'n' },
        { "SingleProc", no_argument,    NULL,    's' },
        { "InterProc",  no_argument,    NULL,    'i' },
        { "Bounds",     no_argument,    NULL,    'x' },
        { "Permissions",no_argument,    NULL,    'y' },
        { "Quiet",      no_argument,    NULL,    'q' },
        { "Verbose",    no_argument,    NULL,    'v' },
    };
    int opt, option_index;

    app_opts.print = 1;

    /* Check for environment variables */
    char *single_proc = getenv("PYTILIA_SINGLE_PROCESS");
    if (single_proc && (strcasecmp(single_proc, "yes") == 0)) {
        app_opts.process_type = 1;
    }

    char *inter_proc = getenv("PYTILIA_INTER_PROCESS");
    if (inter_proc && (strcasecmp(inter_proc, "yes") == 0)) {
        app_opts.process_type = 2;
    }

    char *no_proc = getenv("PYTILIA_NO_PROCESS");
    if (no_proc && (strcasecmp(no_proc, "yes") == 0)) {
        app_opts.process_type = 3;
    }

    char *bounds = getenv("PYTILIA_BOUNDS_ERROR");
    if (bounds && (strcasecmp(bounds, "yes") == 0)) {
        app_opts.bounds_error = 1;
    }

    char *permissions = getenv("PYTILIA_PERMISSIONS_ERROR");
    if (permissions && (strcasecmp(permissions, "yes") == 0)) {
        app_opts.permissions_error = 1;
    }

    char *quiet = getenv("PYTILIA_QUIET");
    if (quiet && (strcasecmp(quiet, "yes") == 0)) {
        app_opts.print = 0;
    }

    char *verbose = getenv("PYTILIA_VERBOSE");
    if (verbose && (strcasecmp(verbose, "yes") == 0)) {
        app_opts.print = 2;
    }

    static const struct rte_mbuf_dynfield tsc_dynfield_desc = {
        .name = "example_bbdev_dynfield_tsc",
        .size = sizeof(tsc_t),
        .align = __alignof__(tsc_t),
    };

    /* init EAL */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    argc -= ret;
    argv += ret;

    /* Check command line arguments */
    while ((opt = getopt_long(argc, argv, short_opts, lgopts, &option_index))
            != EOF)
        switch (opt) {
        case 's':
        /** Single Process **/
            app_opts.process_type = 1;
            break;
        case 'i':
        /** Inter Process **/
            app_opts.process_type = 2;
            break;
        case 'n':
        /** No Processing **/
            app_opts.process_type = 3;
            break;
        case 'x':
        /** Bounds Error **/
            app_opts.bounds_error = 1;
            break;
        case 'y':
        /** Permissions Error **/
            app_opts.permissions_error = 1;
            break;
        case 'q':
        /** Quiet Output **/
            app_opts.print = 0;
            break;
        case 'v':
        /** Verbose Output **/
            app_opts.print = 2;
            break;
        default:
            printf(usage, argv[0]);
            return -1;
        }

    if (!app_opts.process_type) {
        printf("ERROR! No process type selected!");
        return 1;
    }

    if (app_opts.print) {
        if (app_opts.process_type == 1) {
            printf("Selected single, CHERI process.\n");

            if (app_opts.bounds_error) {
                printf("Raise a capability bounds error.\n");
            } else if (app_opts.permissions_error) {
                printf("Raise a capability permissions error.\n");
            }
        } else if (app_opts.process_type == 2) {
            printf("Selected inter-process communications.\n");
        } else if (app_opts.process_type == 3) {
            printf("Selected no packet processing.\n");
        }
        if (app_opts.print == 2) {
            printf("Verbose output selected.\n");
        }
    }

    optind = 1; /* reset getopt lib */

    nb_ports = rte_eth_dev_count_avail();
    if (app_opts.print)
        printf("Port count %u\n", nb_ports);

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", 13400, MBUF_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    tsc_dynfield_offset = rte_mbuf_dynfield_register(&tsc_dynfield_desc);
    if (tsc_dynfield_offset < 0)
        rte_exit(EXIT_FAILURE, "Cannot register mbuf field\n");

    /* initialize all ports */
    RTE_ETH_FOREACH_DEV(portid)
        if (port_init(portid, mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8"\n", portid);

    if (rte_lcore_count() > 1 && app_opts.print)
        printf("\nWARNING: Too many enabled lcores - App uses only 1 lcore\n");

    /* call lcore_main on main core only */
    lcore_main();
    return 0;
}
