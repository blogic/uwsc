/*
 * Copyright (C) 2026 John Crispin <john@phrozen.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <libubox/utils.h>

#include "client-internal.h"
#include "client-defaults.h"
#include "teeny-sha1.h"
#include "util.h"
#include "log.h"
#include "ws.h"

#define UWSC_WS_MAGIC_STRING "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/* 64-bit byte order conversion functions */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static inline uint64_t htonll(uint64_t value) {
	return ((uint64_t)htonl(value & 0xFFFFFFFF) << 32) | htonl(value >> 32);
}

static inline uint64_t ntohll(uint64_t value) {
	return ((uint64_t)ntohl(value & 0xFFFFFFFF) << 32) | ntohl(value >> 32);
}
#else
static inline uint64_t htonll(uint64_t value) { return value; }
static inline uint64_t ntohll(uint64_t value) { return value; }
#endif

__hidden char *
uwsc_client_generate_ws_key(void)
{
	unsigned char random_bytes[16];
	int fd;
	ssize_t ret;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return NULL;

	ret = read(fd, random_bytes, sizeof(random_bytes));
	close(fd);

	if (ret != sizeof(random_bytes))
		return NULL;

	char *encoded = xalloc(B64_ENCODE_LEN(sizeof(random_bytes)));
	b64_encode(random_bytes, sizeof(random_bytes), encoded, B64_ENCODE_LEN(sizeof(random_bytes)));
	return encoded;
}

__hidden bool
uwsc_client_verify_accept_key(const char *ws_key, const char *accept_key)
{
	char combined[256];
	unsigned char sha1_hash[20];
	char *expected_accept;
	bool result;

	if (!ws_key || !accept_key)
		return false;

	snprintf(combined, sizeof(combined), "%s%s", ws_key, UWSC_WS_MAGIC_STRING);

	uwsc_sha1digest(sha1_hash, NULL, (const uint8_t *)combined, strlen(combined));

	expected_accept = xalloc(B64_ENCODE_LEN(sizeof(sha1_hash)));
	b64_encode(sha1_hash, sizeof(sha1_hash), expected_accept, B64_ENCODE_LEN(sizeof(sha1_hash)));
	result = (strcmp(accept_key, expected_accept) == 0);

	free(expected_accept);
	return result;
}

static void
generate_mask_key(uint8_t mask[4])
{
	int fd;
	ssize_t ret;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd >= 0) {
		ret = read(fd, mask, 4);
		close(fd);
		if (ret == 4)
			return;
	}

	/* Fallback to simple random if /dev/urandom fails */
	for (int i = 0; i < 4; i++)
		mask[i] = rand() & 0xFF;
}

static void
mask_payload(uint8_t *data, size_t len, const uint8_t mask[4])
{
	for (size_t i = 0; i < len; i++)
		data[i] ^= mask[i % 4];
}

static int
uwsc_client_ws_send_frame(uwsc_client_t *client, uwsc_ws_opcode_t opcode,
                         const void *data, size_t len, bool fin)
{
	uint8_t header[14];
	uint8_t mask[4];
	uint8_t *payload;
	struct iovec iov[2];
	size_t header_len = 2;
	ssize_t sent;

	if (!client || client->state != UWSC_CLIENT_STATE_CONNECTED)
		return -1;

	/* Generate masking key (required for client frames) */
	generate_mask_key(mask);

	/* Build frame header */
	uwsc_ws_frame_header_t *hdr = (uwsc_ws_frame_header_t *)header;
	hdr->fin = fin ? 1 : 0;
	hdr->rsv1 = 0;
	hdr->rsv2 = 0;
	hdr->rsv3 = 0;
	hdr->opcode = opcode;
	hdr->mask = 1; /* Always mask client frames */

	if (len < 126) {
		hdr->len = len;
	}
	else if (len < 65536) {
		hdr->len = 126;
		*(uint16_t *)(header + 2) = htons(len);
		header_len += 2;
	}
	else {
		hdr->len = 127;
		*(uint64_t *)(header + 2) = htonll(len);
		header_len += 8;
	}

	/* Add mask key */
	memcpy(header + header_len, mask, 4);
	header_len += 4;

	/* Prepare payload with masking */
	payload = xalloc(len);
	memcpy(payload, data, len);
	mask_payload(payload, len, mask);

	/* Check if we have pending data to send first */
	if (uwsc_client_send_buffer_pending(client) > 0) {
		/* Must buffer this frame until previous data is sent */
		int ret = uwsc_client_send_buffer_append(client, header, header_len);
		if (ret == 0 && len > 0) {
			ret = uwsc_client_send_buffer_append(client, payload, len);
		}
		free(payload);
		return ret;
	}

	/* For SSL connections, combine header and payload into single buffer */
	if (client->use_ssl && len > 0) {
		uint8_t *combined = xalloc(header_len + len);
		memcpy(combined, header, header_len);
		memcpy(combined + header_len, payload, len);

		sent = uwsc_client_send_buffered(client, combined, header_len + len);
		free(combined);
		free(payload);
		return sent;
	}

	/* For non-SSL, try to send both parts */
	iov[0].iov_base = header;
	iov[0].iov_len = header_len;
	iov[1].iov_base = payload;
	iov[1].iov_len = len;

	sent = uwsc_conn_sendv(&client->conn, iov, (len > 0) ? 2 : 1);

	if (sent < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			/* Buffer entire frame for later */
			int ret = uwsc_client_send_buffer_append(client, header, header_len);
			if (ret == 0 && len > 0) {
				ret = uwsc_client_send_buffer_append(client, payload, len);
			}
			free(payload);
			return ret;
		}
		free(payload);
		return -1;
	}

	/* Handle partial sends */
	size_t total_len = header_len + len;
	if ((size_t)sent < total_len) {
		/* Figure out what wasn't sent and buffer it */
		if ((size_t)sent < header_len) {
			/* Partial header sent */
			int ret = uwsc_client_send_buffer_append(client,
			                                        header + sent,
			                                        header_len - sent);
			if (ret == 0 && len > 0) {
				ret = uwsc_client_send_buffer_append(client, payload, len);
			}
			free(payload);
			return ret;
		} else {
			/* Header sent, partial payload */
			size_t payload_sent = sent - header_len;
			int ret = uwsc_client_send_buffer_append(client,
			                                        payload + payload_sent,
			                                        len - payload_sent);
			free(payload);
			return ret;
		}
	}

	free(payload);
	return 0;
}

/* Send fragmented message if it exceeds fragment threshold */
static int
uwsc_client_ws_send_fragmented(uwsc_client_t *client, uwsc_ws_opcode_t opcode,
                               const void *data, size_t len)
{
	/* Use 8KB fragments to ensure multiple can fit in our 64KB buffer */
	const size_t fragment_size = 8192; /* 8KB fragments */
	const uint8_t *ptr = (const uint8_t *)data;
	size_t offset = 0;
	int ret;

	/* Send first fragment with original opcode */
	size_t chunk = (len - offset > fragment_size) ? fragment_size : len - offset;
	ret = uwsc_client_ws_send_frame(client, opcode, ptr + offset, chunk, chunk == len);
	if (ret < 0)
		return ret;
	offset += chunk;

	/* Send continuation fragments */
	while (offset < len) {
		chunk = (len - offset > fragment_size) ? fragment_size : len - offset;
		bool is_final = (offset + chunk >= len);
		ret = uwsc_client_ws_send_frame(client, UWSC_OPCODE_CONTINUATION, ptr + offset, chunk, is_final);
		if (ret < 0)
			return ret;
		offset += chunk;
	}

	return 0;
}

int
uwsc_client_ws_send_text(uwsc_client_t *client, const char *text)
{
	if (!text)
		return -1;

	size_t len = strlen(text);

	/* Send as fragments if it exceeds threshold for text frames */
	if (len > UWSC_MAX_TEXT_FRAME_SIZE)
		return uwsc_client_ws_send_fragmented(client, UWSC_OPCODE_TEXT, text, len);

	return uwsc_client_ws_send_frame(client, UWSC_OPCODE_TEXT, text, len, true);
}

int
uwsc_client_ws_send_binary(uwsc_client_t *client, const void *data, size_t len)
{
	if (!data && len > 0)
		return -1;

	/* Send as fragments if it exceeds threshold */
	if (len > UWSC_MAX_BINARY_FRAME_SIZE)
		return uwsc_client_ws_send_fragmented(client, UWSC_OPCODE_BINARY, data, len);

	return uwsc_client_ws_send_frame(client, UWSC_OPCODE_BINARY, data, len, true);
}

int
uwsc_client_ws_send_ping(uwsc_client_t *client, const void *data, size_t len)
{
	if (len > 125) /* Ping payload must be <= 125 bytes */
		return -1;

	return uwsc_client_ws_send_frame(client, UWSC_OPCODE_PING, data, len, true);
}

int
uwsc_client_ws_send_pong(uwsc_client_t *client, const void *data, size_t len)
{
	if (len > 125) /* Pong payload must be <= 125 bytes */
		return -1;

	return uwsc_client_ws_send_frame(client, UWSC_OPCODE_PONG, data, len, true);
}

int
uwsc_client_ws_send_close(uwsc_client_t *client, uint16_t code, const char *reason)
{
	uint8_t payload[127];
	size_t len = 0;

	if (code > 0) {
		*(uint16_t *)payload = htons(code);
		len = 2;

		if (reason) {
			size_t reason_len = strlen(reason);
			if (reason_len > 123)
				reason_len = 123; /* Max close reason length */

			memcpy(payload + 2, reason, reason_len);
			len += reason_len;
		}
	}

	return uwsc_client_ws_send_frame(client, UWSC_OPCODE_CLOSE, payload, len, true);
}

static void
unmask_payload(uint8_t *data, size_t len, const uint8_t mask[4])
{
	for (size_t i = 0; i < len; i++)
		data[i] ^= mask[i % 4];
}


static bool
uwsc_client_process_ws_frame(uwsc_client_t *client, uwsc_ws_opcode_t opcode,
                             const uint8_t *payload, size_t len, bool fin)
{
	/* Control frames (PING, PONG, CLOSE) cannot be fragmented */
	if (opcode >= UWSC_OPCODE_CLOSE) {
		switch (opcode) {
		case UWSC_OPCODE_PING:
			/* Respond with pong */
			uwsc_client_ws_send_pong(client, payload, len);
			break;

		case UWSC_OPCODE_PONG:
			/* Pong received - could be used for keepalive */
			uwsc_log_debug(NULL, "WebSocket pong received (%zu bytes)", len);
			break;

		case UWSC_OPCODE_CLOSE:
			uwsc_log_debug(NULL, "WebSocket close frame received");
			uwsc_client_set_state(client, UWSC_CLIENT_STATE_CLOSING);
			break;

		default:
			uwsc_log_warn(NULL, "Unsupported WebSocket opcode: %u", opcode);
			break;
		}
		return false;
	}

	/* Handle data frames (TEXT, BINARY, CONTINUATION) */
	if (opcode == UWSC_OPCODE_CONTINUATION) {
		/* Must have an active fragmented message */
		if (!client->fragment.in_fragment) {
			uwsc_client_set_error(client, "Unexpected continuation frame");
			return false;
		}
	} else {
		/* Starting a new message */
		if (client->fragment.in_fragment) {
			uwsc_client_set_error(client, "New message started before previous fragment completed");
			return false;
		}

		if (!fin) {
			/* First fragment of a fragmented message */
			client->fragment.in_fragment = true;
			client->fragment.first_opcode = opcode;
			client->fragment.size = 0;
		}
	}

	/* If this is a fragmented message, buffer the data */
	if (client->fragment.in_fragment) {
		/* Ensure we have enough capacity */
		size_t new_size = client->fragment.size + len;

		/* Check against maximum frame size */
		if (new_size > UWSC_MAX_FRAME_SIZE) {
			uwsc_client_set_error(client, "Fragment reassembly exceeds maximum frame size");
			free(client->fragment.buffer);
			client->fragment.buffer = NULL;
			client->fragment.size = 0;
			client->fragment.capacity = 0;
			client->fragment.in_fragment = false;
			return false;
		}

		/* Grow buffer if needed */
		if (new_size > client->fragment.capacity) {
			size_t new_capacity = client->fragment.capacity ? client->fragment.capacity * 2 : 4096;
			while (new_capacity < new_size)
				new_capacity *= 2;

			if (new_capacity > UWSC_MAX_FRAME_SIZE)
				new_capacity = UWSC_MAX_FRAME_SIZE;

			uint8_t *new_buffer = xalloc(new_capacity);
			if (client->fragment.size > 0)
				memcpy(new_buffer, client->fragment.buffer, client->fragment.size);
			free(client->fragment.buffer);
			client->fragment.buffer = new_buffer;
			client->fragment.capacity = new_capacity;
		}

		/* Append this fragment's data */
		memcpy(client->fragment.buffer + client->fragment.size, payload, len);
		client->fragment.size += len;

		/* If this is the final fragment, deliver the complete message */
		if (fin) {
			if (client->fragment.first_opcode == UWSC_OPCODE_TEXT) {
				/* For text messages, ensure null termination */
				char *text = xalloc(client->fragment.size + 1);
				memcpy(text, client->fragment.buffer, client->fragment.size);
				text[client->fragment.size] = '\0';
				bool exit_occurred = uwsc_ucode_on_recv(client, text, client->fragment.size, false);
				free(text);
				if (exit_occurred)
					return true;
			} else if (client->fragment.first_opcode == UWSC_OPCODE_BINARY) {
				if (uwsc_ucode_on_recv(client, (const char *)client->fragment.buffer,
				                client->fragment.size, true))
					return true;
			}

			/* Reset fragmentation state */
			client->fragment.in_fragment = false;
			client->fragment.size = 0;
		}
	} else {
		/* Non-fragmented message - deliver immediately */
		switch (opcode) {
		case UWSC_OPCODE_TEXT:
			{
				char *text = xalloc(len + 1);
				memcpy(text, payload, len);
				text[len] = '\0';
				bool exit_occurred = uwsc_ucode_on_recv(client, text, len, false);
				free(text);
				if (exit_occurred)
					return true;
			}
			break;

		case UWSC_OPCODE_BINARY:
			if (uwsc_ucode_on_recv(client, (const char *)payload, len, true))
				return true;  /* Exit called, stop processing */
			break;

		default:
			uwsc_log_warn(NULL, "Unexpected opcode for non-fragmented message: %u", opcode);
			break;
		}
	}
	return false;
}

void
uwsc_client_ws_timeout(struct uloop_timeout *utm)
{
	uwsc_client_t *client = container_of(utm, uwsc_client_t, conn.utm);

	/* Abort if uloop is shutting down */
	if (uloop_cancelling())
		return;

	uloop_fd_delete(&client->conn.ufd);
	uwsc_client_set_state(client, UWSC_CLIENT_STATE_CLOSING);
	uwsc_ucode_on_disconnect(client);
}

void
uwsc_client_ping_cb(struct uloop_timeout *utm)
{
	uwsc_client_t *client = container_of(utm, uwsc_client_t, ping_timer);

	/* Abort if uloop is shutting down */
	if (uloop_cancelling())
		return;

	if (client->state != UWSC_CLIENT_STATE_CONNECTED)
		return;

	uwsc_client_ws_send_ping(client, NULL, 0);

	/* Schedule next ping */
	uloop_timeout_set(&client->ping_timer, client->ping_timeout);
}

/* Read up to want bytes into buf, tracking progress in *pos across calls.
 * Returns 1 once the chunk is complete, 0 to wait for the next ULOOP_READ,
 * -1 on peer close and -2 on a hard receive error. Forward progress re-arms
 * the idle timeout so slowly arriving frames keep the connection alive. */
static int
uwsc_client_ws_recv_chunk(uwsc_client_t *client, uint8_t *buf, size_t want, size_t *pos)
{
	ssize_t received;

	while (*pos < want) {
		received = uwsc_conn_recv(&client->conn, buf + *pos, want - *pos);
		if (received > 0) {
			*pos += (size_t)received;
			if (client->timeout_idle > 0) {
				client->conn.utm.cb = uwsc_client_ws_timeout;
				uloop_timeout_set(&client->conn.utm, client->timeout_idle);
			}
			continue;
		}
		if (received == 0)
			return -1;
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		return -2;
	}

	return 1;
}

static int
uwsc_client_ws_recv_phase(uwsc_client_t *client, uint8_t *buf, size_t want,
                          size_t *pos, const char *what)
{
	int rc = uwsc_client_ws_recv_chunk(client, buf, want, pos);

	if (rc == -1) {
		uwsc_client_set_state(client, UWSC_CLIENT_STATE_CLOSING);
		uwsc_ucode_on_disconnect(client);
	}
	else if (rc == -2) {
		char errbuf[128];

		snprintf(errbuf, sizeof(errbuf), "Failed to read %s", what);
		uwsc_client_set_error(client, errbuf);
	}

	return rc;
}

__hidden void
uwsc_client_ws_recv_reset(uwsc_client_t *client)
{
	free(client->ws_recv.payload);
	client->ws_recv.payload = NULL;
	client->ws_recv.payload_pos = 0;
	client->ws_recv.payload_len = 0;
	client->ws_recv.has_mask = false;
	client->ws_recv.hdr_pos = 0;
	client->ws_recv.state = UWSC_WS_RECV_HEADER;
}

static bool
uwsc_client_ws_recv_payload(uwsc_client_t *client)
{
	uint64_t plen = client->ws_recv.payload_len;
	uint8_t opcode = client->ws_recv.opcode;
	bool fin = client->ws_recv.fin;
	uint8_t *payload;

	if (plen > 0 && !client->ws_recv.payload) {
		size_t max_size = (opcode == UWSC_OPCODE_TEXT)
			? UWSC_MAX_TEXT_FRAME_SIZE : UWSC_MAX_FRAME_SIZE;

		if (plen > max_size) {
			char errbuf[256];

			snprintf(errbuf, sizeof(errbuf),
			         "Received WebSocket frame too large: %llu bytes (max %zu bytes for %s frames)",
			         (unsigned long long)plen, max_size,
			         (opcode == UWSC_OPCODE_TEXT) ? "text" : "binary");
			uwsc_client_set_error(client, errbuf);
			return false;
		}

		client->ws_recv.payload = xalloc((size_t)plen);
		client->ws_recv.payload_pos = 0;
	}

	if (plen > 0) {
		if (uwsc_client_ws_recv_phase(client, client->ws_recv.payload,
		                              (size_t)plen, &client->ws_recv.payload_pos,
		                              "frame payload") <= 0)
			return false;

		if (client->ws_recv.has_mask)
			unmask_payload(client->ws_recv.payload, (size_t)plen,
			               client->ws_recv.mask);
	}

	payload = client->ws_recv.payload;
	client->ws_recv.payload = NULL;
	uwsc_client_ws_recv_reset(client);

	bool exit_occurred = uwsc_client_process_ws_frame(client, opcode, payload,
	                                                  (size_t)plen, fin);

	free(payload);

	return !exit_occurred;
}

static bool
uwsc_client_ws_recv_advance(uwsc_client_t *client)
{
	uwsc_ws_frame_header_t *hdr;

	switch (client->ws_recv.state) {
	case UWSC_WS_RECV_HEADER:
		if (uwsc_client_ws_recv_phase(client, client->ws_recv.hdr_buf, 2,
		                              &client->ws_recv.hdr_pos,
		                              "WebSocket frame header") <= 0)
			return false;

		hdr = (uwsc_ws_frame_header_t *)client->ws_recv.hdr_buf;
		client->ws_recv.fin = hdr->fin;
		client->ws_recv.opcode = hdr->opcode;
		client->ws_recv.has_mask = hdr->mask;
		client->ws_recv.hdr_pos = 0;

		if (hdr->len == 126) {
			client->ws_recv.state = UWSC_WS_RECV_EXT_LEN16;
		}
		else if (hdr->len == 127) {
			client->ws_recv.state = UWSC_WS_RECV_EXT_LEN64;
		}
		else {
			client->ws_recv.payload_len = hdr->len;
			client->ws_recv.state = client->ws_recv.has_mask
				? UWSC_WS_RECV_MASK_KEY : UWSC_WS_RECV_PAYLOAD;
		}
		return true;

	case UWSC_WS_RECV_EXT_LEN16:
		if (uwsc_client_ws_recv_phase(client, client->ws_recv.hdr_buf, 2,
		                              &client->ws_recv.hdr_pos,
		                              "extended payload length") <= 0)
			return false;

		client->ws_recv.payload_len = ntohs(*(uint16_t *)client->ws_recv.hdr_buf);
		client->ws_recv.hdr_pos = 0;
		client->ws_recv.state = client->ws_recv.has_mask
			? UWSC_WS_RECV_MASK_KEY : UWSC_WS_RECV_PAYLOAD;
		return true;

	case UWSC_WS_RECV_EXT_LEN64:
		if (uwsc_client_ws_recv_phase(client, client->ws_recv.hdr_buf, 8,
		                              &client->ws_recv.hdr_pos,
		                              "extended payload length") <= 0)
			return false;

		client->ws_recv.payload_len = ntohll(*(uint64_t *)client->ws_recv.hdr_buf);
		client->ws_recv.hdr_pos = 0;
		client->ws_recv.state = client->ws_recv.has_mask
			? UWSC_WS_RECV_MASK_KEY : UWSC_WS_RECV_PAYLOAD;
		return true;

	case UWSC_WS_RECV_MASK_KEY:
		/* Server frames should not be masked, tolerate them anyway */
		if (uwsc_client_ws_recv_phase(client, client->ws_recv.mask, 4,
		                              &client->ws_recv.hdr_pos,
		                              "frame mask") <= 0)
			return false;

		client->ws_recv.hdr_pos = 0;
		client->ws_recv.state = UWSC_WS_RECV_PAYLOAD;
		return true;

	case UWSC_WS_RECV_PAYLOAD:
		return uwsc_client_ws_recv_payload(client);
	}

	return false;
}

void
uwsc_client_ws_cb(struct uloop_fd *ufd, unsigned int events)
{
	uwsc_client_t *client = container_of(ufd, uwsc_client_t, conn.ufd);
	bool prev_in_callback;

	/* Abort if uloop is shutting down */
	if (uloop_cancelling())
		return;

	/* Handle write events - flush send buffer */
	if (events & ULOOP_WRITE) {
		if (uwsc_client_send_buffer_flush(client) < 0) {
			uwsc_client_set_error(client, "Failed to flush send buffer");
			return;
		}
		/* If buffer is now empty, stop watching for write events */
		if (uwsc_client_send_buffer_pending(client) == 0) {
			uloop_fd_add(&client->conn.ufd, ULOOP_READ);
		}
	}

	/* Handle read events */
	if (!(events & ULOOP_READ))
		return;

	if (client->state == UWSC_CLIENT_STATE_CLOSING ||
	    client->state == UWSC_CLIENT_STATE_DISCONNECTED) {
		uloop_fd_delete(&client->conn.ufd);
		return;
	}

	/* Frame processing runs callbacks that may disconnect or error the
	 * client; defer its destruction while the loop still dereferences it.
	 * The fd is removed by the timeout / error / disconnect paths. */
	prev_in_callback = client->in_callback;
	client->in_callback = true;

	while (client->state == UWSC_CLIENT_STATE_CONNECTED &&
	       uwsc_client_ws_recv_advance(client))
		;

	client->in_callback = prev_in_callback;
}

/* Whether conn->buf holds a complete frame that can be processed without
 * touching the socket. Frames whose claimed length exceeds the frame limit
 * count as complete: the read path errors on them right after the header. */
__hidden bool
uwsc_client_ws_buffered_frame_complete(uwsc_client_t *client)
{
	uwsc_connection_t *conn = &client->conn;
	const uint8_t *p = conn->buf.pos;
	size_t avail = conn->buf.end - conn->buf.pos;
	size_t need = 2;
	uint64_t payload_len;
	uwsc_ws_frame_header_t hdr;

	if (avail < need)
		return false;

	memcpy(&hdr, p, sizeof(hdr));
	payload_len = hdr.len;

	if (hdr.len == 126) {
		need += 2;
		if (avail < need)
			return false;
		payload_len = ((uint64_t)p[2] << 8) | p[3];
	}
	else if (hdr.len == 127) {
		need += 8;
		if (avail < need)
			return false;
		payload_len = 0;
		for (int i = 0; i < 8; i++)
			payload_len = (payload_len << 8) | p[2 + i];
	}

	if (hdr.mask)
		need += 4;

	if (payload_len > UWSC_MAX_FRAME_SIZE)
		return true;

	return avail >= need + payload_len;
}

int
uwsc_client_ws_start_receive(uwsc_client_t *client)
{
	if (!client || client->state != UWSC_CLIENT_STATE_CONNECTED)
		return -1;

	/* Note: The fd is already registered with uloop from HTTP phase */
	/* We just change the callback in client-http.c now */

	return 0;
}

/* Synchronous message receive function */
int
uwsc_client_ws_receive_sync(uwsc_client_t *client, char **data, size_t *len, bool *binary)
{
	uint8_t header_buf[14];
	uint8_t *payload = NULL;
	ssize_t received;
	size_t header_len, payload_len;
	uwsc_ws_frame_header_t *hdr;
	uint8_t mask[4];
	bool has_mask;

	if (!client || client->state != UWSC_CLIENT_STATE_CONNECTED)
		return -1;

	/* Read frame header (minimum 2 bytes) */
	received = uwsc_conn_recv(&client->conn, header_buf, 2);
	if (received < 2) {
		uwsc_client_set_error(client, "Failed to read WebSocket frame header");
		return -1;
	}

	hdr = (uwsc_ws_frame_header_t *)header_buf;
	has_mask = hdr->mask;
	header_len = 2;

	/* Read extended payload length */
	if (hdr->len == 126) {
		received = uwsc_conn_recv(&client->conn, header_buf + 2, 2);
		if (received < 2) {
			uwsc_client_set_error(client, "Failed to read extended payload length");
			return -1;
		}
		payload_len = ntohs(*(uint16_t *)(header_buf + 2));
		header_len += 2;
	}
	else if (hdr->len == 127) {
		received = uwsc_conn_recv(&client->conn, header_buf + 2, 8);
		if (received < 8) {
			uwsc_client_set_error(client, "Failed to read extended payload length");
			return -1;
		}
		payload_len = ntohll(*(uint64_t *)(header_buf + 2));
		header_len += 8;
	}
	else {
		payload_len = hdr->len;
	}

	/* Read masking key if present */
	if (has_mask) {
		received = uwsc_conn_recv(&client->conn, mask, 4);
		if (received < 4) {
			uwsc_client_set_error(client, "Failed to read frame mask");
			return -1;
		}
		header_len += 4;
	}

	/* Read payload */
	if (payload_len > 0) {
		/* Apply same limit for synchronous receive */
		size_t max_size = (*binary) ? UWSC_MAX_FRAME_SIZE : UWSC_MAX_TEXT_FRAME_SIZE;
		if (payload_len > max_size) {
			char errbuf[256];
			snprintf(errbuf, sizeof(errbuf),
			         "Received WebSocket frame too large: %zu bytes (max %zu bytes for %s frames)",
			         payload_len, max_size, (*binary) ? "binary" : "text");
			uwsc_client_set_error(client, errbuf);
			return -1;
		}

		payload = xalloc(payload_len + 1);
		size_t total_received = 0;
		while (total_received < payload_len) {
			received = uwsc_conn_recv(&client->conn, payload + total_received, payload_len - total_received);
			if (received <= 0) {
				free(payload);
				uwsc_client_set_error(client, "Failed to read frame payload");
				return -1;
			}
			total_received += received;
		}

		/* Unmask payload if masked */
		if (has_mask)
			unmask_payload(payload, payload_len, mask);

		payload[payload_len] = '\0'; /* Null terminate for text */
	}

	/* Handle different frame types */
	switch (hdr->opcode) {
	case UWSC_OPCODE_TEXT:
		*data = (char *)payload;
		*len = payload_len;
		*binary = false;
		return 0;

	case UWSC_OPCODE_BINARY:
		*data = (char *)payload;
		*len = payload_len;
		*binary = true;
		return 0;

	case UWSC_OPCODE_PING:
		/* Auto-respond to ping */
		uwsc_client_ws_send_pong(client, payload, payload_len);
		free(payload);
		/* Continue reading next frame */
		return uwsc_client_ws_receive_sync(client, data, len, binary);

	case UWSC_OPCODE_PONG:
		/* Ignore pong frames */
		free(payload);
		return uwsc_client_ws_receive_sync(client, data, len, binary);

	case UWSC_OPCODE_CLOSE:
		free(payload);
		uwsc_client_set_state(client, UWSC_CLIENT_STATE_CLOSING);
		return -1; /* Connection closed */

	default:
		free(payload);
		uwsc_client_set_error(client, "Unsupported WebSocket opcode");
		return -1;
	}
}
