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

#ifndef UWSC_CLIENT_INTERNAL_H
#define UWSC_CLIENT_INTERNAL_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <libubox/uloop.h>

#include "client.h"
#include "util.h"
#include "client-defaults.h"

typedef struct uwsc_client uwsc_client_t;
typedef struct uwsc_client_config uwsc_client_config_t;

typedef enum {
	UWSC_CLIENT_STATE_DISCONNECTED,
	UWSC_CLIENT_STATE_DNS_RESOLVE,
	UWSC_CLIENT_STATE_TCP_CONNECT,
	UWSC_CLIENT_STATE_SSL_HANDSHAKE,
	UWSC_CLIENT_STATE_HTTP_UPGRADE,
	UWSC_CLIENT_STATE_WS_HANDSHAKE,
	UWSC_CLIENT_STATE_CONNECTED,
	UWSC_CLIENT_STATE_CLOSING,
	UWSC_CLIENT_STATE_ERROR
} uwsc_client_state_t;

typedef enum {
	UWSC_WS_RECV_HEADER,
	UWSC_WS_RECV_EXT_LEN16,
	UWSC_WS_RECV_EXT_LEN64,
	UWSC_WS_RECV_MASK_KEY,
	UWSC_WS_RECV_PAYLOAD
} uwsc_ws_recv_state_t;

struct uwsc_client_config {
	uint32_t timeout_connect;
	uint32_t timeout_idle;
	uint32_t ping_timeout;
	uint32_t reconnect_timeout;
	bool ssl_verify;
	bool ssl_verify_hostname;
	char *ca_cert_path;
	char **protocols;
	size_t protocol_count;
	char *user_agent;
};

struct uwsc_client {
	uwsc_connection_t conn;
	uwsc_client_state_t state;

	char *url;
	char *host;
	char *path;
	uint16_t port;
	bool use_ssl;

	char *ws_key;
	char **protocols;
	size_t protocol_count;
	char *selected_protocol;

	uwsc_buffer_t send_buf;
	uwsc_buffer_t recv_buf;

	struct uloop_timeout ping_timer;
	struct uloop_timeout reconnect_timer;
	struct uloop_timeout connect_timer;

	uint32_t reconnect_count;

	/* HTTP response buffer */
	char http_buffer[UWSC_HTTP_BUFFER_SIZE];
	size_t http_buffer_len;

	union {
		struct sockaddr unspec;
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} sa_peer;

	uint32_t timeout_connect;
	uint32_t timeout_idle;
	uint32_t ping_timeout;
	uint32_t reconnect_timeout;
	bool ssl_verify;
	char *ca_cert_path;
	char *user_agent;

	struct {
		char *reason;
		uint16_t code;
	} close_info;

	/* WebSocket fragmentation support */
	struct {
		uint8_t *buffer;        /* Reassembly buffer for fragments */
		size_t size;            /* Current size of data in buffer */
		size_t capacity;        /* Allocated capacity of buffer */
		uint8_t first_opcode;   /* Opcode of first fragment */
		bool in_fragment;       /* Currently reassembling fragments */
	} fragment;

	/* Per-frame receive state. A TCP segment boundary may fall inside the
	 * 2-byte frame header, the extended length, the masking key or the
	 * payload, so every phase must survive a short read and resume on the
	 * next ULOOP_READ wake-up instead of failing the connection. */
	struct {
		uwsc_ws_recv_state_t state;
		size_t hdr_pos;
		uint8_t hdr_buf[8];     /* fits the 8-byte 64-bit extended length */
		bool fin;
		uint8_t opcode;
		bool has_mask;
		uint8_t mask[4];
		uint64_t payload_len;
		uint8_t *payload;       /* allocated once payload_len is known */
		size_t payload_pos;
	} ws_recv;

	void *ucode_ctx;
	bool in_callback;
};

__hidden int uwsc_client_parse_url(const char *url, char **host, uint16_t *port,
                                   char **path, bool *use_ssl);
__hidden int uwsc_client_resolve_host(uwsc_client_t *client);
__hidden int uwsc_client_tcp_connect(uwsc_client_t *client);
__hidden int uwsc_client_ssl_handshake(uwsc_client_t *client);
__hidden int uwsc_client_http_upgrade(uwsc_client_t *client);

__hidden void uwsc_client_set_state(uwsc_client_t *client, uwsc_client_state_t state);
__hidden void uwsc_client_set_error(uwsc_client_t *client, const char *error);

__hidden char *uwsc_client_generate_ws_key(void);
__hidden bool uwsc_client_verify_accept_key(const char *ws_key, const char *accept_key);

__hidden bool uwsc_client_ssl_init(uwsc_client_t *client);
__hidden bool uwsc_client_ssl_connect(uwsc_client_t *client);

__hidden int uwsc_client_ws_send_text(uwsc_client_t *client, const char *text);
__hidden int uwsc_client_ws_send_binary(uwsc_client_t *client, const void *data, size_t len);
__hidden int uwsc_client_ws_send_ping(uwsc_client_t *client, const void *data, size_t len);
__hidden int uwsc_client_ws_send_pong(uwsc_client_t *client, const void *data, size_t len);
__hidden int uwsc_client_ws_send_close(uwsc_client_t *client, uint16_t code, const char *reason);
__hidden int uwsc_client_ws_start_receive(uwsc_client_t *client);
__hidden int uwsc_client_ws_receive_sync(uwsc_client_t *client, char **data, size_t *len, bool *binary);
__hidden bool uwsc_client_ws_buffered_frame_complete(uwsc_client_t *client);
__hidden void uwsc_client_ws_recv_reset(uwsc_client_t *client);

/* WebSocket callback functions - exposed for client-http.c */
__hidden void uwsc_client_ws_timeout(struct uloop_timeout *utm);
__hidden void uwsc_client_ws_cb(struct uloop_fd *ufd, unsigned int events);
__hidden void uwsc_client_ping_cb(struct uloop_timeout *utm);

/* Core client API functions */
__hidden uwsc_client_t *uwsc_client_create(const uwsc_client_config_t *config);
__hidden void uwsc_client_destroy(uwsc_client_t *client);
__hidden int uwsc_client_connect(uwsc_client_t *client, const char *url);
__hidden int uwsc_client_send(uwsc_client_t *client, const void *data, size_t len, bool binary);
__hidden int uwsc_client_close(uwsc_client_t *client, uint16_t code, const char *reason);
__hidden uwsc_client_state_t uwsc_client_get_state(uwsc_client_t *client);
__hidden const char *uwsc_client_get_selected_protocol(uwsc_client_t *client);

/* ucode callback functions */
__hidden bool uwsc_ucode_on_connect(uwsc_client_t *client);
__hidden bool uwsc_ucode_on_disconnect(uwsc_client_t *client);
__hidden bool uwsc_ucode_on_error(uwsc_client_t *client, const char *error);
__hidden bool uwsc_ucode_on_recv(uwsc_client_t *client, const char *data, size_t len, bool binary);

/* Send buffer management */
__hidden void uwsc_client_send_buffer_init(uwsc_client_t *client);
__hidden size_t uwsc_client_send_buffer_space(uwsc_client_t *client);
__hidden size_t uwsc_client_send_buffer_pending(uwsc_client_t *client);
__hidden int uwsc_client_send_buffer_append(uwsc_client_t *client, const void *data, size_t len);
__hidden int uwsc_client_send_buffer_flush(uwsc_client_t *client);
__hidden int uwsc_client_send_buffered(uwsc_client_t *client, const void *data, size_t len);
__hidden void uwsc_client_send_buffer_clear(uwsc_client_t *client);

#endif /* UWSC_CLIENT_INTERNAL_H */
