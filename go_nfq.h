// Copyright (C) 2015 Martin Garton <garton@gmail.com>

#ifndef _NETFILTER_H
#define _NETFILTER_H

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

extern uint callback(int id, unsigned char *data, int len, void *nfqp);

static int nf_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		       struct nfq_data *nfa, void *nfqp)
{
	uint32_t id = -1;
	struct nfqnl_msg_packet_hdr *ph = NULL;
	unsigned char *buffer = NULL;
	int ret = 0;
	int verdict = 0;

	ph = nfq_get_msg_packet_hdr(nfa);
	id = ntohl(ph->packet_id);

	ret = nfq_get_payload(nfa, &buffer);
	verdict = callback(id, buffer, ret, nfqp);

	return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

struct go_nfq_params {
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	u_int16_t queue;
	void *nfqp;
	u_int32_t maxInQueue;
	u_int packetSize;
	int fd;
	int closePipefd[2];
};

static inline int go_nfq_init(struct go_nfq_params *params, u_int16_t queue,
			      void *nfqp, u_int32_t maxInQueue,
			      u_int packetSize)
{

	params->h = nfq_open();
	if (!params->h) {
		fprintf(stderr, "error during nfq_open()\n");
		return -1;
	}

	if (nfq_unbind_pf(params->h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		return -1;
	}

	if (nfq_bind_pf(params->h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		return -1;
	}

	params->qh = nfq_create_queue(params->h, queue, &nf_callback, nfqp);
	if (!params->qh) {
		perror("error during nfq_create_queue()\n");
		nfq_close(params->h);
		return -1;
	}

	if (nfq_set_queue_maxlen(params->qh, maxInQueue) < 0) {
		fprintf(stderr, "error during nfq_set_queue_maxlen()\n");
		nfq_destroy_queue(params->qh);
		nfq_close(params->h);
		return -1;
	}

	if (nfq_set_mode(params->qh, NFQNL_COPY_PACKET, packetSize) < 0) {
		fprintf(stderr, "error during nfq_set_mode()\n");
		nfq_destroy_queue(params->qh);
		nfq_close(params->h);
		return -1;
	}

	params->fd = nfq_fd(params->h);
	if (params->fd <= 0) {
		fprintf(stderr, "error during nfq_fd()\n");
		nfq_destroy_queue(params->qh);
		nfq_close(params->h);
		return -1;
	}

	if (pipe(params->closePipefd) == -1) {
		perror("pipe");
		nfq_destroy_queue(params->qh);
		nfq_close(params->h);
		return -1;
	}

	return 0;
}

static inline void go_nfq_run(struct go_nfq_params *params)
{
	char buf[4096] __attribute__ ((aligned));
	int rv;

	int maxfd = params->fd;
	if (maxfd < params->closePipefd[0]) {
		maxfd = params->closePipefd[0];
	}

	while (1) {
		fd_set fdset;
		FD_ZERO(&fdset);
		FD_SET(params->fd, &fdset);
		FD_SET(params->closePipefd[0], &fdset);

		int selected = select(maxfd + 1, &fdset, NULL, NULL, NULL);
		if (selected <= 0) {
			perror("select failed, returning");
			return;
		}
		if (FD_ISSET(params->closePipefd[0], &fdset)) {
			nfq_destroy_queue(params->qh);
			nfq_close(params->h);
			return;
		} else if (FD_ISSET(params->fd, &fdset)) {
			rv = recv(params->fd, buf, sizeof(buf), 0);
			if (rv == 0) {
				perror("read failed, exiting read loop");
				return;
			}
			nfq_handle_packet(params->h, buf, rv);
		} else {
			fprintf(stderr,
				"unexpected fd: %d is not %d or %d. exiting read loop\n",
				selected, params->fd, params->closePipefd[0]);
			return;
		}
	}
}

static inline void go_nfq_stop(struct go_nfq_params *params)
{
	close(params->closePipefd[1]);
}

#endif
