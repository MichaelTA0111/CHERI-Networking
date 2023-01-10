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

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 10000
#define SERVERPORT "4950"


static struct {
	int process_type;
	int bounds_error;
	int permissions_error;
} app_opts;

struct addrinfo *servinfo, *p;

typedef uint64_t tsc_t;
static int tsc_dynfield_offset = -1;

static const char short_opts[] =
	"s"	/* Use single CHERI secured process */
	"i"	/* Use IPC model */
	"x"	/* Raise capability bounds error */
	"y"	/* Raise capability permissions error */
	;

static const char usage[] =
	"%s EAL_ARGS -- [-s Single Process] [-i Inter Process] [-x Bounds Error] [-y Permissions Error] \n";

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
	},
};

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
	printf("Port %u MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8
			" %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}

static int
create_socket() {
	int sockfd;
	struct addrinfo hints;
	int rv;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET6; // set to AF_INET to use IPv4
	hints.ai_socktype = SOCK_DGRAM;

	if ((rv = getaddrinfo("localhost", SERVERPORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return -1;
	}

	// loop through all the results and make a socket
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("talker: socket");
			continue;
		}
		break;
	}

	if (p == NULL) {
		fprintf(stderr, "talker: failed to create socket\n");
		return -1;
	}

	return sockfd;
}

/*
 * Main thread that does the work, reading from INPUT_PORT
 * and writing to OUTPUT_PORT
 */
static  __rte_noreturn void
lcore_main(void)
{
	uint16_t port;
	int sockfd;

	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets.\n", rte_lcore_id());

	if ((sockfd = create_socket()) < 0) {
		printf("Error creating socket!\n");
		return;
	}
	
	for (;;) {
		RTE_ETH_FOREACH_DEV(port) {
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);
			if (unlikely(nb_rx == 0))
				continue;

			printf("Got %d packets\n", nb_rx);
			int i;
			for (i = 0; i < nb_rx; i++) {
				size_t read_len =  rte_pktmbuf_pkt_len(bufs[i]);
				printf("\nBuffer %d: Address %p, Length %u\n", i, read_len, bufs[i]);
				printf("Capability: Permissions 0x%lX, Address %p, Length %u\n",
						cheri_getperm(bufs[i]->buf_addr),
						bufs[i]->buf_addr,
						cheri_getlen(bufs[i]->buf_addr));
				char *c;
				int j, k = 0;

				c = bufs[i]->buf_addr;

				// Raise a permissions error
				if (app_opts.permissions_error) {
					printf("Attempting to write to read-only permissions.\n");
					c = cheri_andperm(c, ~CHERI_PERM_STORE);
					*c = 0xFE;
				}

				// Raise a bounds error
				if (app_opts.bounds_error) {
					c = bufs[i]->buf_addr;
					printf("Attempting to read beyond the capability bounds.\n");
					read_len += 128;
					for (j = 0; j < read_len; j++) {
						printf("%02X ", c[bufs[i]->data_off + j]);
						k++;
						if (k == 16) {
							printf("\n");
							k = 0;
						}
					}
				} else {
					rte_pktmbuf_dump(stdout, bufs[i], read_len);
				}

				int numbytes;
				if ((numbytes = sendto(sockfd, &c[bufs[i]->data_off], read_len, 0,
						p->ai_addr, p->ai_addrlen)) == -1) {
					perror("Error with sendto command");
					exit(1);
				}

				printf("Sent %d bytes to localhost.\n", numbytes);
			}

			if (nb_rx) {
				uint16_t buf;
				for (buf = 0; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);
			}
		}
	}

	// TODO: Add a way to naturally end the program after reading in all from the pcap file
	freeaddrinfo(servinfo);
}

/* Main function, does initialisation and calls the per-lcore functions */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	uint16_t nb_ports, portid;
	struct option lgopts[] = {
		{ NULL,         no_argument,    0,       0 },
		{ "SingleProc", no_argument,    NULL,    's' },
		{ "InterProc",  no_argument,    NULL,    'i' },
		{ "Bounds",     no_argument,    NULL,    'x' },
		{ "Permissions",no_argument,    NULL,    'y' },
		{ "HWTS",       no_argument,    NULL,    't' },
	};
	int opt, option_index;

	char *single_proc = getenv("PYTILIA_SINGLE_PROCESS");
	if (single_proc && (strcasecmp(single_proc, "yes") == 0)) {
		printf("Use single process.\n");
		app_opts.process_type = 1;
	}

	char *inter_proc = getenv("PYTILIA_INTER_PROCESS");
	if (inter_proc && (strcasecmp(inter_proc, "yes") == 0)) {
		if (app_opts.process_type)
			printf("WARNING! Overwriting process type!\n");

		printf("Use inter process communications.\n");
		app_opts.process_type = 2;
	}

	char *bounds = getenv("PYTILIA_BOUNDS_ERROR");
	if (bounds && (strcasecmp(bounds, "yes") == 0)) {
		printf("Raise a capability bounds error.\n");
		app_opts.bounds_error = 1;
	}

	char *permissions = getenv("PYTILIA_PERMISSIONS_ERROR");
	if (permissions && (strcasecmp(permissions, "yes") == 0)) {
		printf("Raise a capability permissions error.\n");
		app_opts.permissions_error = 1;
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

	while ((opt = getopt_long(argc, argv, short_opts, lgopts, &option_index))
			!= EOF)
		switch (opt) {
		case 's':
		/** Single Process **/
			if (app_opts.process_type)
				printf("WARNING! Overwriting process type!\n");

			printf("Use single process.\n");
			app_opts.process_type = 1;
			break;
		case 'i':
		/** Inter Process **/
			if (app_opts.process_type)
				printf("WARNING! Overwriting process type!\n");

			printf("Use inter process communications.\n");
			app_opts.process_type = 2;
			break;
		case 'x':
		/** Bounds Error **/
			printf("Raise a capability bounds error.\n");
			app_opts.bounds_error = 1;
			break;
		case 'y':
		/** Permissions Error **/
			printf("Raise a capability permissions error.\n");
			app_opts.permissions_error = 1;
			break;
		default:
			printf(usage, argv[0]);
			return -1;
		}

	optind = 1; /* reset getopt lib */
	nb_ports = rte_eth_dev_count_avail();
	printf("Port count %u\n", nb_ports);

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
		13400, MBUF_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	tsc_dynfield_offset =
		rte_mbuf_dynfield_register(&tsc_dynfield_desc);
	if (tsc_dynfield_offset < 0)
		rte_exit(EXIT_FAILURE, "Cannot register mbuf field\n");

	/* initialize all ports */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8"\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many enabled lcores - "
			"App uses only 1 lcore\n");

	/* call lcore_main on main core only */
	lcore_main();
	return 0;
}
