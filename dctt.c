/*-
 * Copyright (C) 2012, 2016 Michael Tuexen
 * Copyright (C) 2012 Irene Ruengeler
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.	IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define LINE_LENGTH (1024)
#define BUFFER_SIZE (1<<16)
#define NUMBER_OF_CHANNELS (100)
#define NUMBER_OF_STREAMS (100)

#define DATA_CHANNEL_PPID_CONTROL   50
#define DATA_CHANNEL_PPID_DOMSTRING 51
#define DATA_CHANNEL_PPID_BINARY    52

/* As specified in the W3C specification */
#define DATA_CHANNEL_CONNECTING 1
#define DATA_CHANNEL_OPEN       2
#define DATA_CHANNEL_CLOSING    3
#define DATA_CHANNEL_CLOSED     4

#define DATA_CHANNEL_FLAGS_SEND_REQ 0x00000001
#define DATA_CHANNEL_FLAGS_SEND_ACK 0x00000002
#define DATA_CHANNEL_FLAGS_I_RESET  0x00000004
#define DATA_CHANNEL_FLAGS_O_RESET  0x00000008

struct channel {
	uint16_t sid;
	uint16_t pr_policy;
	uint32_t pr_value;
	uint8_t unordered;
	uint8_t type;
	uint16_t priority;
	char *label;
	char *protocol;
	uint8_t state;
	uint32_t flags;
};

struct peer_connection {
	struct channel channels[NUMBER_OF_CHANNELS];
	pthread_mutex_t mutex;
	int fd;
	int client;
} peer_connection;


#define DATA_CHANNEL_ACK_MESSAGE_TYPE           2
#define DATA_CHANNEL_OPEN_MESSAGE_TYPE          3

#define DATA_CHANNEL_RELIABLE                          0x00
#define DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT           0x01
#define DATA_CHANNEL_PARTIAL_RELIABLE_TIMED            0x02
#define DATA_CHANNEL_RELIABLE_UNORDERED                0x80
#define DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED 0x81
#define DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED  0x82
#define DATA_CHANNEL_UNORDERED                         0x80

struct rtcweb_datachannel_open {
	uint8_t message_type; /* DATA_CHANNEL_OPEN */
	uint8_t channel_type;
	uint16_t priority;
	uint32_t reliability_parameter;
	uint16_t label_length;
	uint16_t protocol_length;
	char label_and_protocol[];
} __attribute__((packed));

struct rtcweb_datachannel_ack {
	uint8_t message_type; /* DATA_CHANNEL_ACK */
} __attribute__((packed));

static void
init_peer_connection(struct peer_connection *pc, int fd, int client)
{
	uint32_t i;
	struct channel *channel;

	for (i = 0; i < NUMBER_OF_CHANNELS; i++) {
		channel = &(pc->channels[i]);
		channel->sid = i;
		channel->pr_policy = SCTP_PR_SCTP_NONE;
		channel->pr_value = 0;
		channel->unordered = 0;
		channel->type = 0xff;
		channel->priority = 0;
		channel->label = NULL;
		channel->protocol = NULL;
		channel->state = DATA_CHANNEL_CLOSED;
		channel->flags = 0;
	}
	pc->fd = fd;
	pc->client = client;
	pthread_mutex_init(&pc->mutex, NULL);
}

static void
lock_peer_connection(struct peer_connection *pc)
{
	pthread_mutex_lock(&pc->mutex);
}

static void
unlock_peer_connection(struct peer_connection *pc)
{
	pthread_mutex_unlock(&pc->mutex);
}

static struct channel *
find_channel_by_id(struct peer_connection *pc, uint16_t id)
{
	if (id < NUMBER_OF_STREAMS) {
		return (&(pc->channels[id]));
	} else {
		return (NULL);
	}
}

static struct channel *
find_free_channel(struct peer_connection *pc)
{
	uint32_t i;

	for (i = pc->client ? 0 : 1; i < NUMBER_OF_CHANNELS; i += 2) {
		if (pc->channels[i].state == DATA_CHANNEL_CLOSED) {
			break;
		}
	}
	if (i >= NUMBER_OF_CHANNELS) {
		return (NULL);
	} else {
		return (&(pc->channels[i]));
	}
}

static int
send_data_channel_open_message(int fd,
                               uint16_t sid,
                               uint8_t channel_type,
                               uint16_t priority,
                               uint32_t reliability_parameter,
                               char *label,
                               char *protocol)
{
	struct rtcweb_datachannel_open dc_open;
	struct sctp_sndinfo sndinfo;
	struct iovec iov[3];

	assert(label != NULL);
	assert(strlen(label) < 65536);
	assert(protocol != NULL);
	assert(strlen(protocol) < 65536);
	dc_open.message_type = DATA_CHANNEL_OPEN_MESSAGE_TYPE;
	dc_open.channel_type = channel_type;
	dc_open.priority = htons(priority);
	dc_open.reliability_parameter = htonl(reliability_parameter);
	dc_open.label_length = htons((uint16_t)strlen(label));
	dc_open.protocol_length = htons((uint16_t)strlen(protocol));
	iov[0].iov_base = &dc_open;
	iov[0].iov_len = sizeof(struct rtcweb_datachannel_open);
	iov[1].iov_base = label;
	iov[1].iov_len = strlen(label);
	iov[2].iov_base = protocol;
	iov[2].iov_len = strlen(protocol);
	memset(&sndinfo, 0, sizeof(struct sctp_sndinfo));
	sndinfo.snd_sid = sid;
	sndinfo.snd_flags = SCTP_EOR;
	sndinfo.snd_ppid = htonl(DATA_CHANNEL_PPID_CONTROL);
	if (sctp_sendv(fd,
	               iov, 3,
	               NULL, 0,
	               &sndinfo, (socklen_t)sizeof(struct sctp_sndinfo),
	               SCTP_SENDV_SNDINFO, 0) < 0) {
		perror("sctp_sendv");
		return (0);
	} else {
		return (1);
	}
}

static int
send_data_channel_ack_message(int fd,
                              uint16_t sid)
{
	struct rtcweb_datachannel_ack dc_ack;
	struct sctp_sndinfo sndinfo;
	struct iovec iov[1];

	dc_ack.message_type = DATA_CHANNEL_ACK_MESSAGE_TYPE;
	iov[0].iov_base = &dc_ack;
	iov[0].iov_len = sizeof(struct rtcweb_datachannel_ack);
	memset(&sndinfo, 0, sizeof(struct sctp_sndinfo));
	sndinfo.snd_sid = sid;
	sndinfo.snd_flags = SCTP_EOR;
	sndinfo.snd_ppid = htonl(DATA_CHANNEL_PPID_CONTROL);
	if (sctp_sendv(fd,
	               iov, 1,
	               NULL, 0,
	               &sndinfo, (socklen_t)sizeof(struct sctp_sndinfo),
	               SCTP_SENDV_SNDINFO, 0) < 0) {
		perror("sctp_sendv");
		return (0);
	} else {
		return (1);
	}
}

static void
send_deferred_messages(struct peer_connection *pc)
{
	uint32_t i;
	struct channel *channel;

	for (i = 0; i < NUMBER_OF_CHANNELS; i++) {
		channel = &(pc->channels[i]);
		if (channel->flags & DATA_CHANNEL_FLAGS_SEND_REQ) {
			if (send_data_channel_open_message(pc->fd, channel->sid, channel->type, channel->priority, channel->pr_value, channel->label, channel->protocol)) {
				channel->flags &= ~DATA_CHANNEL_FLAGS_SEND_REQ;
			} else {
				if (errno != EAGAIN) {
					/* XXX: error handling */
				}
			}
		}
		if (channel->flags & DATA_CHANNEL_FLAGS_SEND_ACK) {
			if (send_data_channel_ack_message(pc->fd, channel->sid)) {
				channel->flags &= ~DATA_CHANNEL_FLAGS_SEND_ACK;
			} else {
				if (errno != EAGAIN) {
					/* XXX: error handling */
				}
			}
		}
	}
	return;
}

static struct channel *
open_channel(struct peer_connection *pc,
             uint8_t unordered,
             uint16_t pr_policy, uint32_t pr_value,
             uint16_t priority,
             char *label,
             char *protocol)
{
	struct channel *channel;

	if ((pr_policy != SCTP_PR_SCTP_NONE) &&
	    (pr_policy != SCTP_PR_SCTP_RTX) &&
	    (pr_policy != SCTP_PR_SCTP_TTL)) {
		return (NULL);
	}
	if ((unordered != 0) && (unordered != 1)) {
		return (NULL);
	}
	if ((pr_policy == SCTP_PR_SCTP_NONE) && (pr_value != 0)) {
		return (NULL);
	}
	if ((label == NULL) || (protocol == NULL)) {
		return (NULL);
	}
	if ((strlen(label) > 65535) || (strlen(protocol) > 65535)) {
		return (NULL);
	}
	if ((channel = find_free_channel(pc)) == NULL) {
		return (NULL);
	}
	channel->pr_policy = pr_policy;
	channel->pr_value = pr_value;
	channel->unordered = unordered;
	switch (pr_policy) {
	case SCTP_PR_SCTP_NONE:
		channel->type = DATA_CHANNEL_RELIABLE;
		break;
	case SCTP_PR_SCTP_RTX:
		channel->type = DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT;
		break;
	case SCTP_PR_SCTP_TTL:
		channel->type = DATA_CHANNEL_PARTIAL_RELIABLE_TIMED;
		break;
	}
	if (unordered) {
		channel->type |= DATA_CHANNEL_UNORDERED;
	}
	channel->priority = priority;
	channel->label = strdup(label);
	channel->protocol = strdup(protocol);
	channel->state = DATA_CHANNEL_CONNECTING;
	channel->flags = 0;
	if (send_data_channel_open_message(pc->fd, channel->sid, channel->type, channel->priority, channel->pr_value, channel->label, channel->protocol)) {
		channel->state = DATA_CHANNEL_CONNECTING;
	} else {
		if (errno == EAGAIN) {
			channel->flags |= DATA_CHANNEL_FLAGS_SEND_REQ;
		} else {
			channel->pr_policy = SCTP_PR_SCTP_NONE;
			channel->pr_value = 0;
			channel->unordered = 0;
			channel->type = 0xff;
			channel->priority = 0;
			free(channel->label);
			channel->label = NULL;
			free(channel->protocol);
			channel->protocol = NULL;
			channel->state = DATA_CHANNEL_CLOSED;
			channel->flags = 0;
			channel = NULL;
		}
	}
	return (channel);
}

static int
send_user_message(struct peer_connection *pc, struct channel *channel, char *message, size_t length)
{
	struct sctp_sendv_spa spa;
	struct iovec iov;

	if (channel == NULL) {
		return (0);
	}
	if ((channel->state != DATA_CHANNEL_OPEN) &&
	    (channel->state != DATA_CHANNEL_CONNECTING)) {
		/* XXX: What to do in other states */
		return (0);
	}

	iov.iov_base = message;
	iov.iov_len = length;
	memset(&spa, 0, sizeof(struct sctp_sendv_spa));
	spa.sendv_sndinfo.snd_sid = channel->sid;
	if ((channel->state == DATA_CHANNEL_OPEN) &&
	    (channel->unordered)) {
		spa.sendv_sndinfo.snd_flags = SCTP_EOR | SCTP_UNORDERED;
	} else {
		spa.sendv_sndinfo.snd_flags = SCTP_EOR;
	}
	spa.sendv_sndinfo.snd_ppid = htonl(DATA_CHANNEL_PPID_DOMSTRING);
	spa.sendv_flags = SCTP_SEND_SNDINFO_VALID;
	if ((channel->pr_policy == SCTP_PR_SCTP_TTL) ||
	    (channel->pr_policy == SCTP_PR_SCTP_RTX)) {
		spa.sendv_prinfo.pr_policy = channel->pr_policy;
		spa.sendv_prinfo.pr_value = channel->pr_value;
		spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
	}
	if (sctp_sendv(pc->fd,
	               &iov, 1,
	               NULL, 0,
	               &spa, (socklen_t)sizeof(struct sctp_sendv_spa),
	               SCTP_SENDV_SPA, 0) < 0) {
		perror("sctp_sendv");
		return (0);
	} else {
		return (1);
	}
}

static void
reset_outgoing_stream(struct peer_connection *pc, uint16_t sid)
{
	struct sctp_reset_streams *srs;
	size_t len;

	len = sizeof(struct sctp_reset_streams) + sizeof(uint16_t);
	srs = (struct sctp_reset_streams *)malloc(len);
	if (srs == NULL) {
		return;
	}
	memset(srs, 0, len);
	srs->srs_flags = SCTP_STREAM_RESET_OUTGOING;
	srs->srs_number_streams = 1;
	srs->srs_stream_list[0] = sid;
	if (setsockopt(pc->fd, IPPROTO_SCTP, SCTP_RESET_STREAMS, srs, (socklen_t)len) < 0) {
		perror("setsockopt");
		printf("reset_outgoing_stream: Can't reset stream %u.\n", sid);
	}
	free(srs);
}

static void
close_channel(struct peer_connection *pc, struct channel *channel)
{
	if (channel == NULL) {
		return;
	}
	if (channel->state != DATA_CHANNEL_OPEN) {
		return;
	}
	reset_outgoing_stream(pc, channel->sid);
	channel->state = DATA_CHANNEL_CLOSING;
	return;
}

static void
handle_open_ack_message(struct peer_connection *pc,
                        struct rtcweb_datachannel_ack *ack,
                        size_t length, uint16_t sid)
{
	struct channel *channel;

	channel = find_channel_by_id(pc, sid);
	if (channel == NULL) {
		/* XXX: some error handling */
		return;
	}
	if (channel->state == DATA_CHANNEL_OPEN) {
		return;
	}
	if (channel->state != DATA_CHANNEL_CONNECTING) {
		/* XXX: error handling */
		return;
	}
	channel->state = DATA_CHANNEL_OPEN;
	return;
}

static void
handle_open_request_message(struct peer_connection *pc,
                            struct rtcweb_datachannel_open *dc_open,
                            size_t length,
                            uint16_t sid)
{
	struct channel *channel;
	uint16_t label_length;
	uint16_t protocol_length;

	label_length = ntohs(dc_open->label_length);
	protocol_length = ntohs(dc_open->protocol_length);
	if (sizeof(struct rtcweb_datachannel_open) + label_length + protocol_length != length) {
		printf("handle_open_request_message: invalid packet.\n");
	}
	if ((channel = find_channel_by_id(pc, sid)) == NULL) {
		printf("handle_open_request_message: Can't find channel for id = %u.\n",
		       sid);
		/* XXX: some error handling */
		return;
	}
	if (channel->state != DATA_CHANNEL_CLOSED) {
		printf("handle_open_request_message: channel for id = %u not in CLOSED (state = %u).\n",
		       sid, channel->state);
		/* XXX: some error handling */
		return;
	}
	channel->type = dc_open->channel_type;
	switch (dc_open->channel_type) {
	case DATA_CHANNEL_RELIABLE:
		channel->pr_policy = SCTP_PR_SCTP_NONE;
		channel->pr_value = ntohl(dc_open->reliability_parameter);
		channel->unordered = 0;
		break;
	case DATA_CHANNEL_RELIABLE_UNORDERED:
		channel->pr_policy = SCTP_PR_SCTP_NONE;
		channel->pr_value = ntohl(dc_open->reliability_parameter);
		channel->unordered = 1;
		break;
	case DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT:
		channel->pr_policy = SCTP_PR_SCTP_RTX;
		channel->pr_value = ntohl(dc_open->reliability_parameter);
		channel->unordered = 0;
		break;
	case DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED:
		channel->pr_policy = SCTP_PR_SCTP_RTX;
		channel->pr_value = ntohl(dc_open->reliability_parameter);
		channel->unordered = 1;
		break;
	case DATA_CHANNEL_PARTIAL_RELIABLE_TIMED:
		channel->pr_policy = SCTP_PR_SCTP_TTL;
		channel->pr_value = ntohl(dc_open->reliability_parameter);
		channel->unordered = 0;
		break;
	case DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED:
		channel->pr_policy = SCTP_PR_SCTP_TTL;
		channel->pr_value = ntohl(dc_open->reliability_parameter);
		channel->unordered = 1;
		break;
	default:
		/* XXX error handling */
		break;
	}
	channel->type = dc_open->channel_type;
	channel->priority = ntohs(dc_open->priority);
	channel->label = malloc((size_t)label_length + 1);
	memcpy(channel->label, dc_open->label_and_protocol, label_length);
	channel->label[label_length] = '\0';
	channel->protocol = malloc((size_t)protocol_length + 1);
	memcpy(channel->protocol, dc_open->label_and_protocol + label_length, protocol_length);
	channel->label[protocol_length] = '\0';
	channel->state = DATA_CHANNEL_OPEN;
	channel->flags = 0;
	if (send_data_channel_ack_message(pc->fd, sid) == 0) {
		if (errno == EAGAIN) {
			channel->flags |= DATA_CHANNEL_FLAGS_SEND_ACK;
		} else {
			/* XXX error handling*/
		}
	}
}

static void
handle_unknown_message(char *msg, size_t length, uint16_t i_stream)
{
	/* XXX: Send an error message */
	return;
}

static void
handle_data_message(struct peer_connection *pc,
                    char *buffer, size_t length, uint16_t sid)
{
	struct channel *channel;

	channel = find_channel_by_id(pc, sid);
	if (channel == NULL) {
		/* XXX: Some error handling */
		return;
	}
	if (channel->state == DATA_CHANNEL_CONNECTING) {
		/* Implicit ACK */
		channel->state = DATA_CHANNEL_OPEN;
	}
	if (channel->state != DATA_CHANNEL_OPEN) {
		/* XXX: What about other states? */
		/* XXX: Some error handling */
		return;
	} else {
		/* Assuming DATA_CHANNEL_PPID_DOMSTRING */
		/* XXX: Protect for non 0 terminated buffer */
		printf("Message received of length %lu on channel with id %d: %.*s\n",
		       length, channel->sid, (int)length, buffer);
	}
	return;
}

static void
handle_message(struct peer_connection *pc, char *buffer, size_t length, uint32_t ppid, uint16_t sid)
{
	struct rtcweb_datachannel_open *dc_open;
	struct rtcweb_datachannel_ack *dc_ack;
	uint8_t type;

	switch (ppid) {
	case DATA_CHANNEL_PPID_CONTROL:
		if (length < sizeof(uint8_t)) {
			return;
		}
		type = *(uint8_t *)buffer;
		switch (type) {
		case DATA_CHANNEL_ACK_MESSAGE_TYPE:
			if (length < sizeof(struct rtcweb_datachannel_ack)) {
				/* XXX: error handling? */
				return;
			}
			dc_ack = (struct rtcweb_datachannel_ack *)buffer;
			handle_open_ack_message(pc, dc_ack, length, sid);
			break;
		case DATA_CHANNEL_OPEN_MESSAGE_TYPE:
			if (length < sizeof(struct rtcweb_datachannel_open)) {
				/* XXX: error handling? */
				return;
			}
			dc_open = (struct rtcweb_datachannel_open *)buffer;
			handle_open_request_message(pc, dc_open, length, sid);
			break;
		default:
			handle_unknown_message(buffer, length, sid);
			break;
		}
		break;
	case DATA_CHANNEL_PPID_DOMSTRING:
	case DATA_CHANNEL_PPID_BINARY:
		handle_data_message(pc, buffer, length, sid);
		break;
	default:
		printf("Message of length %lu, PPID %u on stream %u received.\n",
		       length, ppid, sid);
		break;
	}
}

static void
handle_association_change_event(struct sctp_assoc_change *sac)
{
	unsigned int i, n;

	printf("Association change ");
	switch (sac->sac_state) {
	case SCTP_COMM_UP:
		printf("SCTP_COMM_UP");
		break;
	case SCTP_COMM_LOST:
		printf("SCTP_COMM_LOST");
		break;
	case SCTP_RESTART:
		printf("SCTP_RESTART");
		break;
	case SCTP_SHUTDOWN_COMP:
		printf("SCTP_SHUTDOWN_COMP");
		break;
	case SCTP_CANT_STR_ASSOC:
		printf("SCTP_CANT_STR_ASSOC");
		break;
	default:
		printf("UNKNOWN");
		break;
	}
	printf(", streams (in/out) = (%u/%u)",
	       sac->sac_inbound_streams, sac->sac_outbound_streams);
	n = sac->sac_length - sizeof(struct sctp_assoc_change);
	if (((sac->sac_state == SCTP_COMM_UP) ||
	     (sac->sac_state == SCTP_RESTART)) && (n > 0)) {
		printf(", supports");
		for (i = 0; i < n; i++) {
			switch (sac->sac_info[i]) {
			case SCTP_ASSOC_SUPPORTS_PR:
				printf(" PR");
				break;
			case SCTP_ASSOC_SUPPORTS_AUTH:
				printf(" AUTH");
				break;
			case SCTP_ASSOC_SUPPORTS_ASCONF:
				printf(" ASCONF");
				break;
			case SCTP_ASSOC_SUPPORTS_MULTIBUF:
				printf(" MULTIBUF");
				break;
			case SCTP_ASSOC_SUPPORTS_RE_CONFIG:
				printf(" RE-CONFIG");
				break;
			default:
				printf(" UNKNOWN(0x%02x)", sac->sac_info[i]);
				break;
			}
		}
	} else if (((sac->sac_state == SCTP_COMM_LOST) ||
	            (sac->sac_state == SCTP_CANT_STR_ASSOC)) && (n > 0)) {
		printf(", ABORT =");
		for (i = 0; i < n; i++) {
			printf(" 0x%02x", sac->sac_info[i]);
		}
	}
	printf(".\n");
	if ((sac->sac_state == SCTP_CANT_STR_ASSOC) ||
	    (sac->sac_state == SCTP_SHUTDOWN_COMP) ||
	    (sac->sac_state == SCTP_COMM_LOST)) {
		exit(0);
	}
	return;
}

static void
handle_peer_address_change_event(struct sctp_paddr_change *spc)
{
	char addr_buf[INET6_ADDRSTRLEN];
	const char *addr;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	switch (spc->spc_aaddr.ss_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)&spc->spc_aaddr;
		addr = inet_ntop(AF_INET, &sin->sin_addr, addr_buf, INET6_ADDRSTRLEN);
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)&spc->spc_aaddr;
		addr = inet_ntop(AF_INET6, &sin6->sin6_addr, addr_buf, INET6_ADDRSTRLEN);
		break;
	default:
		break;
	}
	printf("Peer address %s is now ", addr);
	switch (spc->spc_state) {
	case SCTP_ADDR_AVAILABLE:
		printf("SCTP_ADDR_AVAILABLE");
		break;
	case SCTP_ADDR_UNREACHABLE:
		printf("SCTP_ADDR_UNREACHABLE");
		break;
	case SCTP_ADDR_REMOVED:
		printf("SCTP_ADDR_REMOVED");
		break;
	case SCTP_ADDR_ADDED:
		printf("SCTP_ADDR_ADDED");
		break;
	case SCTP_ADDR_MADE_PRIM:
		printf("SCTP_ADDR_MADE_PRIM");
		break;
	case SCTP_ADDR_CONFIRMED:
		printf("SCTP_ADDR_CONFIRMED");
		break;
	default:
		printf("UNKNOWN");
		break;
	}
	printf(" (error = 0x%08x).\n", spc->spc_error);
	return;
}

static void
handle_adaptation_indication(struct sctp_adaptation_event *sai)
{
	printf("Adaptation indication: %x.\n", sai-> sai_adaptation_ind);
	return;
}

static void
handle_shutdown_event(struct sctp_shutdown_event *sse)
{
	printf("Shutdown event.\n");
	/* XXX: notify all channels. */
	return;
}

static void
handle_stream_reset_event(struct peer_connection *pc, struct sctp_stream_reset_event *strrst)
{
	uint32_t n, i;
	struct channel *channel;

	n = (strrst->strreset_length - sizeof(struct sctp_stream_reset_event)) / sizeof(uint16_t);
	printf("Stream reset event: flags = %x, ", strrst->strreset_flags);
	if (strrst->strreset_flags & SCTP_STREAM_RESET_INCOMING_SSN) {
		if (strrst->strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) {
			printf("incoming/");
		}
		printf("incoming ");
	}
	if (strrst->strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) {
		printf("outgoing ");
	}
	printf("stream ids = ");
	for (i = 0; i < n; i++) {
		if (i > 0) {
			printf(", ");
		}
		printf("%d", strrst->strreset_stream_list[i]);
	}
	printf(".\n");
	if (!(strrst->strreset_flags & SCTP_STREAM_RESET_DENIED) &&
	    !(strrst->strreset_flags & SCTP_STREAM_RESET_FAILED)) {
		for (i = 0; i < n; i++) {
			channel = find_channel_by_id(pc, strrst->strreset_stream_list[i]);
			if (channel == NULL) {
				printf("handle_stream_reset_event: channel not found for id = %u.\n", strrst->strreset_stream_list[i]);
				continue;
			}
			if (strrst->strreset_flags & SCTP_STREAM_RESET_INCOMING_SSN) {
				if ((channel->flags & DATA_CHANNEL_FLAGS_O_RESET) == 0) {
					reset_outgoing_stream(pc, channel->sid);
				}
				channel->flags |= DATA_CHANNEL_FLAGS_I_RESET;
			}
			if (strrst->strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) {
				channel->flags |= DATA_CHANNEL_FLAGS_O_RESET;
			}
			if ((channel->flags & DATA_CHANNEL_FLAGS_I_RESET) &&
			    (channel->flags & DATA_CHANNEL_FLAGS_I_RESET)) {
				channel->pr_policy = SCTP_PR_SCTP_NONE;
				channel->pr_value = 0;
				channel->unordered = 0;
				channel->type = 0xff;
				channel->priority = 0;
				free(channel->label);
				channel->label = NULL;
				free(channel->protocol);
				channel->protocol = NULL;
				channel->state = DATA_CHANNEL_CLOSED;
				channel->flags = 0;
			}
		}
	}
	return;
}

static void
handle_remote_error_event(struct sctp_remote_error *sre)
{
	size_t i, n;

	n = sre->sre_length - sizeof(struct sctp_remote_error);
	printf("Remote Error (error = 0x%04x): ", sre->sre_error);
	for (i = 0; i < n; i++) {
		printf(" 0x%02x", sre-> sre_data[i]);
	}
	printf(".\n");
	return;
}

static void
handle_send_failed_event(struct sctp_send_failed_event *ssfe)
{
	size_t i, n;

	if (ssfe->ssfe_flags & SCTP_DATA_UNSENT) {
		printf("Unsent ");
	}
	if (ssfe->ssfe_flags & SCTP_DATA_SENT) {
		printf("Sent ");
	}
	if (ssfe->ssfe_flags & ~(SCTP_DATA_SENT | SCTP_DATA_UNSENT)) {
		printf("(flags = %x) ", ssfe->ssfe_flags);
	}
	printf("message with PPID = %d, SID = %d, flags: 0x%04x due to error = 0x%08x",
	       ntohl(ssfe->ssfe_info.snd_ppid), ssfe->ssfe_info.snd_sid,
	       ssfe->ssfe_info.snd_flags, ssfe->ssfe_error);
	n = ssfe->ssfe_length - sizeof(struct sctp_send_failed_event);
	for (i = 0; i < n; i++) {
		printf(" 0x%02x", ssfe->ssfe_data[i]);
	}
	printf(".\n");
	return;
}

static void
handle_notification(struct peer_connection *pc, union sctp_notification *notif, size_t n)
{
	if (notif->sn_header.sn_length != (uint32_t)n) {
		return;
	}
	switch (notif->sn_header.sn_type) {
	case SCTP_ASSOC_CHANGE:
		handle_association_change_event(&(notif->sn_assoc_change));
		break;
	case SCTP_PEER_ADDR_CHANGE:
		handle_peer_address_change_event(&(notif->sn_paddr_change));
		break;
	case SCTP_REMOTE_ERROR:
		handle_remote_error_event(&(notif->sn_remote_error));
		break;
	case SCTP_SHUTDOWN_EVENT:
		handle_shutdown_event(&(notif->sn_shutdown_event));
		break;
	case SCTP_ADAPTATION_INDICATION:
		handle_adaptation_indication(&(notif->sn_adaptation_event));
		break;
	case SCTP_PARTIAL_DELIVERY_EVENT:
		break;
	case SCTP_AUTHENTICATION_EVENT:
		break;
	case SCTP_SENDER_DRY_EVENT:
		break;
	case SCTP_NOTIFICATIONS_STOPPED_EVENT:
		break;
	case SCTP_SEND_FAILED_EVENT:
		handle_send_failed_event(&(notif->sn_send_failed_event));
		break;
	case SCTP_STREAM_RESET_EVENT:
		handle_stream_reset_event(pc, &(notif->sn_strreset_event));
		send_deferred_messages(pc);
		break;
	case SCTP_ASSOC_RESET_EVENT:
		break;
	case SCTP_STREAM_CHANGE_EVENT:
		break;
	default:
		break;
	}
}

static void
print_status(struct peer_connection *pc)
{
	struct sctp_status status;
	socklen_t len;
	uint32_t i;
	struct channel *channel;

	len = (socklen_t)sizeof(struct sctp_status);
	if (getsockopt(pc->fd, IPPROTO_SCTP, SCTP_STATUS, &status, &len) < 0) {
		perror("getsockopt");
		return;
	}
	printf("Association state: ");
	switch (status.sstat_state) {
	case SCTP_CLOSED:
		printf("CLOSED\n");
		break;
	case SCTP_BOUND:
		printf("BOUND\n");
		break;
	case SCTP_LISTEN:
		printf("LISTEN\n");
		break;
	case SCTP_COOKIE_WAIT:
		printf("COOKIE_WAIT\n");
		break;
	case SCTP_COOKIE_ECHOED:
		printf("COOKIE_ECHOED\n");
		break;
	case SCTP_ESTABLISHED:
		printf("ESTABLISHED\n");
		break;
	case SCTP_SHUTDOWN_PENDING:
		printf("SHUTDOWN_PENDING\n");
		break;
	case SCTP_SHUTDOWN_SENT:
		printf("SHUTDOWN_SENT\n");
		break;
	case SCTP_SHUTDOWN_RECEIVED:
		printf("SHUTDOWN_RECEIVED\n");
		break;
	case SCTP_SHUTDOWN_ACK_SENT:
		printf("SHUTDOWN_ACK_SENT\n");
		break;
	default:
		printf("UNKNOWN\n");
		break;
	}
	printf("Number of streams (i/o) = (%u/%u)\n",
	       status.sstat_instrms, status.sstat_outstrms);
	for (i = 0; i < NUMBER_OF_CHANNELS; i++) {
		channel = &(pc->channels[i]);
		if (channel->state == DATA_CHANNEL_CLOSED) {
			continue;
		}
		printf("Channel with id = %u: state ", channel->sid);
		switch (channel->state) {
		case DATA_CHANNEL_CLOSED:
			printf("CLOSED");
			break;
		case DATA_CHANNEL_CONNECTING:
			printf("CONNECTING");
			break;
		case DATA_CHANNEL_OPEN:
			printf("OPEN");
			break;
		case DATA_CHANNEL_CLOSING:
			printf("CLOSING");
			break;
		default:
			printf("UNKNOWN(%d)", channel->state);
			break;
		}
		printf(", ");
		printf("type ");
		switch (channel->type) {
		case DATA_CHANNEL_RELIABLE:
			printf("DATA_CHANNEL_RELIABLE");
			break;
		case DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT:
			printf("DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT");
			break;
		case DATA_CHANNEL_PARTIAL_RELIABLE_TIMED:
			printf("DATA_CHANNEL_PARTIAL_RELIABLE_TIMED");
			break;
		case DATA_CHANNEL_RELIABLE_UNORDERED:
			printf("DATA_CHANNEL_RELIABLE_UNORDERED");
			break;
		case DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED:
			printf("DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED");
			break;
		case DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED:
			printf("DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED");
			break;
		default:
			printf("%u.\n", channel->type);
			break;
		}
		printf(", ");
		if (channel->unordered) {
			printf("unordered, ");
		} else {
			printf("ordered, ");
		}
		printf("priority %u, ", channel->priority);
		switch (channel->pr_policy) {
		case SCTP_PR_SCTP_NONE:
			printf("reliable.\n");
			break;
		case SCTP_PR_SCTP_TTL:
			printf("unreliable (timeout %ums).\n", channel->pr_value);
			break;
		case SCTP_PR_SCTP_RTX:
			printf("unreliable (max. %u rtx).\n", channel->pr_value);
			break;
		default:
			printf("unkown policy %u.\n", channel->pr_policy);
			break;
		}
	}
}

static void *
handle_messages(void *arg)
{
	struct peer_connection *pc;
	struct iovec iov;
	struct sctp_rcvinfo rcvinfo;
	socklen_t infolen;
	unsigned int infotype;
	ssize_t n;
	int flags;
	char buffer[BUFFER_SIZE];

	pc = (struct peer_connection *)arg;
	for (;;) {
		iov.iov_base = buffer;
		iov.iov_len = BUFFER_SIZE;
		memset(&rcvinfo, 0, sizeof(struct sctp_rcvinfo));
		infolen = sizeof(struct sctp_rcvinfo);
		infotype = SCTP_RECVV_NOINFO;
		flags = 0;
		n = sctp_recvv(pc->fd, &iov, 1, NULL, NULL, &rcvinfo, &infolen, &infotype, &flags);
		if (n <= 0) {
			break;
		}
		lock_peer_connection(pc);
		if (flags & MSG_NOTIFICATION) {
			handle_notification(pc, (union sctp_notification *)buffer, n);
		} else {
			if (infotype  == SCTP_RECVV_RCVINFO) {
				handle_message(pc, buffer, n, ntohl(rcvinfo.rcv_ppid), rcvinfo.rcv_sid);
			} else {
				unlock_peer_connection(pc);
				break;
			}
		}
		unlock_peer_connection(pc);
	}
	return (NULL);
}

int
main(int argc, char *argv[])
{
	int fd;
	struct sockaddr_in addr;
	socklen_t addr_len;
	char line[LINE_LENGTH + 1];
	unsigned int unordered, policy, value, priority, id, seconds;
	unsigned int i;
	struct channel *channel;
	const int on = 1;
	struct sctp_assoc_value av;
	struct sctp_event event;
	pthread_t tid;
	struct sctp_initmsg initmsg;
	int client;
	uint16_t event_types[] = {SCTP_ASSOC_CHANGE,
	                          SCTP_PEER_ADDR_CHANGE,
	                          SCTP_REMOTE_ERROR,
	                          SCTP_SHUTDOWN_EVENT,
	                          SCTP_ADAPTATION_INDICATION,
	                          SCTP_SEND_FAILED_EVENT,
	                          SCTP_STREAM_RESET_EVENT,
	                          SCTP_STREAM_CHANGE_EVENT};

	if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) < 0) {
		perror("socket");
	}
	if (setsockopt(fd, IPPROTO_SCTP, SCTP_RECVRCVINFO, &on, sizeof(int)) < 0) {
		perror("setsockopt SCTP_RECVRCVINFO");
	}
	if (setsockopt(fd, IPPROTO_SCTP, SCTP_EXPLICIT_EOR, &on, sizeof(int)) < 0) {
		perror("setsockopt SCTP_EXPLICIT_EOR");
	}
	/* Disable the Explicit Congestion Notification extension */
	av.assoc_id = 0;
	av.assoc_value = 0;
	if (setsockopt(fd, IPPROTO_SCTP, SCTP_ECN_SUPPORTED, (char*) &av, (socklen_t)sizeof(struct sctp_assoc_value)) < 0) {
		perror("setsockopt(SCTP_ECN_SUPPORTED)");
	}
	/* Disable the Address Reconfiguration extension */
	av.assoc_id = 0;
	av.assoc_value = 0;
	if (setsockopt(fd, IPPROTO_SCTP, SCTP_ASCONF_SUPPORTED, (char*) &av, (socklen_t)sizeof(struct sctp_assoc_value)) < 0) {
		perror("setsockopt(SCTP_ASCONF_SUPPORTED)");
	}
	/* Disable the Authentication extension */
	av.assoc_id = 0;
	av.assoc_value = 0;
	if (setsockopt(fd, IPPROTO_SCTP, SCTP_AUTH_SUPPORTED, (char*) &av, (socklen_t)sizeof(struct sctp_assoc_value)) < 0) {
		perror("setsockopt(SCTP_AUTH_SUPPORTED)");
	}
	/* Disable the NR-SACK extension */
	av.assoc_id = 0;
	av.assoc_value = 0;
	if (setsockopt(fd, IPPROTO_SCTP, SCTP_NRSACK_SUPPORTED, (char*) &av, (socklen_t)sizeof(struct sctp_assoc_value)) < 0) {
		perror("setsockopt(SCTP_NRSACK_SUPPORTED)");
	}
	/* Disable the Packet Drop Report extension */
	av.assoc_id = 0;
	av.assoc_value = 0;
	if (setsockopt(fd, IPPROTO_SCTP, SCTP_PKTDROP_SUPPORTED, (char*) &av, (socklen_t)sizeof(struct sctp_assoc_value)) < 0) {
		perror("setsockopt(SCTP_PKTDROP_SUPPORTED)");
	}
	/* Enable the Partial Reliability extension */
	av.assoc_id = SCTP_ALL_ASSOC;
	av.assoc_value = 1;
	if (setsockopt(fd, IPPROTO_SCTP, SCTP_PR_SUPPORTED, &av, (socklen_t)sizeof(struct sctp_assoc_value)) < 0) {
		perror("setsockopt SCTP_PR_SUPPORTED");
	}
	/* Enable the Stream Reconfiguration extension. */
	av.assoc_id = SCTP_ALL_ASSOC;
	av.assoc_value = SCTP_ENABLE_RESET_STREAM_REQ;
	if (setsockopt(fd, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &av, (socklen_t)sizeof(struct sctp_assoc_value)) < 0) {
		perror("setsockopt SCTP_ENABLE_STREAM_RESET");
	}

	/* Enable the events of interest. */
	memset(&event, 0, sizeof(event));
	event.se_assoc_id = SCTP_ALL_ASSOC;
	event.se_on = 1;
	for (i = 0; i < sizeof(event_types)/sizeof(uint16_t); i++) {
		event.se_type = event_types[i];
		if (setsockopt(fd, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0) {
			perror("setsockopt SCTP_EVENT");
		}
	}
	memset(&initmsg, 0, sizeof(struct sctp_initmsg));
	initmsg.sinit_num_ostreams = 65535;
	initmsg.sinit_max_instreams = 65535;
	if (setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(struct sctp_initmsg)) < 0) {
		perror("setsockopt SCTP_INITMSG");
	}

	if (argc > 2) {
		client = 1;
		/* operating as client */
		if (argc > 3) {
			memset(&addr, 0, sizeof(struct sockaddr_in));
			addr.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
			addr.sin_len = sizeof(struct sockaddr_in);
#endif
			addr.sin_addr.s_addr = INADDR_ANY;
			addr.sin_port = htons(atoi(argv[3]));
			if (bind(fd, (const struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0) {
				perror("bind");
			}
		}
		memset(&addr, 0, sizeof(struct sockaddr_in));
		addr.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
		addr.sin_len = sizeof(struct sockaddr_in);
#endif
		addr.sin_addr.s_addr = inet_addr(argv[1]);
		addr.sin_port = htons(atoi(argv[2]));
		if (connect(fd, (const struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0) {
			perror("connect");
		}
		printf("Connected to %s:%d.\n",
		       inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	} else if (argc > 1) {
		int afd;

		/* operating as server */
		client = 0;
		memset(&addr, 0, sizeof(struct sockaddr_in));
		addr.sin_family = AF_INET;
#ifdef HAVE_SIN_LEN
		addr.sin_len = sizeof(struct sockaddr_in);
#endif
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = htons(atoi(argv[1]));
		if (bind(fd, (const struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0) {
			perror("bind");
		}
		if (listen(fd, 1) < 0) {
			perror("listen");
		}
		addr_len = (socklen_t)sizeof(struct sockaddr_in);
		memset(&addr, 0, sizeof(struct sockaddr_in));
		if ((afd = accept(fd, (struct sockaddr *)&addr, &addr_len)) < 0) {
			perror("accept");
		}
		if (close(fd) < 0) {
			perror("close");
		}
		fd = afd;
		printf("Connected to %s:%d.\n",
		       inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	} else {
		printf("Usage: %s local_port when operating as server\n"
		       "       %s remote_addr remote_port [local_port] when operating as client\n",
		       argv[0], argv[0]);
		return (0);
	}

	init_peer_connection(&peer_connection, fd, client);
	pthread_create(&tid, NULL, &handle_messages, &peer_connection);

	for (;;) {
		if (fgets(line, LINE_LENGTH, stdin) == NULL) {
			shutdown(peer_connection.fd, SHUT_WR);
			break;
		}
		if (strncmp(line, "?", strlen("?")) == 0 ||
		    strncmp(line, "help", strlen("help")) == 0) {
			printf("Commands:\n"
			       "open unordered pr_policy pr_value priority - opens a channel\n"
			       "close channel - closes the channel\n"
			       "send channel:string - sends string using channel\n"
			       "status - prints the status\n"
			       "sleep n - sleep for n seconds\n"
			       "help - this message\n");
		} else if (strncmp(line, "status", strlen("status")) == 0) {
			lock_peer_connection(&peer_connection);
			print_status(&peer_connection);
			unlock_peer_connection(&peer_connection);
		} else if (sscanf(line, "open %u %u %u %u", &unordered, &policy, &value, &priority) == 4) {
			lock_peer_connection(&peer_connection);
			channel = open_channel(&peer_connection, (uint8_t)unordered, (uint16_t)policy, (uint32_t)value, priority, "", "");
			unlock_peer_connection(&peer_connection);
			if (channel == NULL) {
				printf("Creating channel failed.\n");
			} else {
				printf("Channel with id %u created.\n", channel->sid);
			}
		} else if (sscanf(line, "close %u", &id) == 1) {
			if (id < NUMBER_OF_CHANNELS) {
				lock_peer_connection(&peer_connection);
				close_channel(&peer_connection, &peer_connection.channels[id]);
				unlock_peer_connection(&peer_connection);
			}
		} else if (sscanf(line, "send %u", &id) == 1) {
			if (id < NUMBER_OF_CHANNELS) {
				char *msg;

				msg = strstr(line, ":");
				if (msg) {
					msg++;
					lock_peer_connection(&peer_connection);
					if (send_user_message(&peer_connection, &peer_connection.channels[id], msg, strlen(msg) - 1)) {
						printf("Message sent.\n");
					} else {
						printf("Message sending failed.\n");
					}
					unlock_peer_connection(&peer_connection);
				}
			}
		} else if (sscanf(line, "sleep %u", &seconds) == 1) {
			sleep(seconds);
		} else {
			printf("Unknown command: %s", line);
		}
	}
	pthread_join(tid, NULL);
	if (close(peer_connection.fd) < 0) {
		perror("close");
	}
	return (0);
}
