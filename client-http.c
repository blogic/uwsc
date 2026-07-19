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
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>

#include "client-internal.h"
#include "client-defaults.h"
#include "client.h"
#include "log.h"

static void uwsc_client_http_timeout(struct uloop_timeout *utm);
static void uwsc_client_http_cb(struct uloop_fd *ufd, unsigned int events);

static int
uwsc_client_send_upgrade_request(uwsc_client_t *client)
{
	char request[UWSC_HTTP_REQUEST_SIZE];
	char protocols_header[UWSC_PROTOCOL_BUFFER_SIZE] = "";
	size_t total_sent = 0;
	ssize_t sent;
	int ret, req_len;

	if (!client->ws_key) {
		client->ws_key = uwsc_client_generate_ws_key();
		if (!client->ws_key) {
			uwsc_client_set_error(client, "Failed to generate WebSocket key");
			return -1;
		}
	}

	if (client->protocols && client->protocol_count > 0) {
		size_t offset = 0;
		int ret;

		for (size_t i = 0; i < client->protocol_count; i++) {
			if (i > 0) {
				ret = snprintf(protocols_header + offset,
				               sizeof(protocols_header) - offset, ", ");
				if (ret < 0 || ret >= (int)(sizeof(protocols_header) - offset)) {
					uwsc_client_set_error(client, "Protocol header too large");
					return -1;
				}
				offset += ret;
			}

			ret = snprintf(protocols_header + offset,
			               sizeof(protocols_header) - offset,
			               "%s", client->protocols[i]);
			if (ret < 0 || ret >= (int)(sizeof(protocols_header) - offset)) {
				uwsc_client_set_error(client, "Protocol header too large");
				return -1;
			}
			offset += ret;
		}
	}

	/* Build Host header - RFC 7230 says don't include default ports */
	char host_header[256];
	bool is_default_port = (client->use_ssl && client->port == 443) ||
	                       (!client->use_ssl && client->port == 80);

	if (is_default_port) {
		ret = snprintf(host_header, sizeof(host_header), "%s", client->host);
	} else {
		ret = snprintf(host_header, sizeof(host_header), "%s:%u", client->host, client->port);
	}

	if (ret < 0 || ret >= (int)sizeof(host_header)) {
		uwsc_client_set_error(client, "Host header too large");
		return -1;
	}

	req_len = snprintf(request, sizeof(request),
		"GET %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Key: %s\r\n"
		"Sec-WebSocket-Version: 13\r\n"
		"%s%s%s"
		"User-Agent: %s\r\n"
		"\r\n",
		client->path, host_header,
		client->ws_key,
		client->protocols ? "Sec-WebSocket-Protocol: " : "",
		client->protocols ? protocols_header : "",
		client->protocols ? "\r\n" : "",
		client->user_agent ? client->user_agent : "uwsc/1.0");

	if (req_len < 0 || req_len >= (int)sizeof(request)) {
		uwsc_client_set_error(client, "HTTP upgrade request too large");
		return -1;
	}

	size_t len = (size_t)req_len;

	while (total_sent < len) {
		sent = uwsc_conn_sendv(&client->conn,
		                   &(struct iovec){ .iov_base = request + total_sent,
		                                    .iov_len = len - total_sent }, 1);
		if (sent < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;

			char errbuf[256];
			snprintf(errbuf, sizeof(errbuf), "Failed to send upgrade request: %s",
			         strerror(errno));
			uwsc_client_set_error(client, errbuf);
			return -1;
		}
		total_sent += sent;
	}

	if (total_sent < len) {
		uwsc_log_debug(NULL, "Partial send (%zu/%zu bytes), will retry", total_sent, len);
	}
	else {
		uwsc_log_debug(NULL, "WebSocket upgrade request sent (%zu bytes)", len);
	}

	return 0;
}

static int
uwsc_client_parse_response_line(const char *line, int *status, char **reason)
{
	const char *p = line;
	char *end;

	if (strncmp(p, "HTTP/1.", 7) != 0)
		return -1;

	p += 7;
	if (*p != '0' && *p != '1')
		return -1;

	p++;
	if (*p != ' ')
		return -1;

	p++;
	*status = strtol(p, &end, 10);
	if (end == p || *status < 100 || *status > 999)
		return -1;

	if (*end == ' ') {
		end++;
		*reason = xstrdup(end);

		char *cr = strchr(*reason, '\r');
		if (cr)
			*cr = '\0';
	}
	else {
		*reason = xstrdup("");
	}

	return 0;
}

static char *
uwsc_client_parse_header(const char *line, const char *name)
{
	size_t name_len = strlen(name);
	const char *p = line;

	if (strncasecmp(p, name, name_len) != 0)
		return NULL;

	p += name_len;
	if (*p != ':')
		return NULL;

	p++;
	while (*p == ' ' || *p == '\t')
		p++;

	char *value = xstrdup(p);
	char *end = strchr(value, '\r');
	if (end)
		*end = '\0';

	return value;
}

static int
uwsc_client_process_response(uwsc_client_t *client, const char *response)
{
	char *line, *response_copy, *saveptr;
	int status = 0;
	char *reason = NULL;
	char *upgrade = NULL, *connection = NULL, *accept_key = NULL, *protocol = NULL;
	bool first_line = true;
	int result = -1;

	response_copy = xstrdup(response);
	line = strtok_r(response_copy, "\n", &saveptr);

	while (line) {
		if (first_line) {
			if (uwsc_client_parse_response_line(line, &status, &reason) != 0) {
				uwsc_client_set_error(client, "Invalid HTTP response line");
				goto cleanup;
			}
			first_line = false;
		}
		else if (strlen(line) > 2) {
			char *value;

			if ((value = uwsc_client_parse_header(line, "Upgrade"))) {
				free(upgrade);
				upgrade = value;
			}
			else if ((value = uwsc_client_parse_header(line, "Connection"))) {
				free(connection);
				connection = value;
			}
			else if ((value = uwsc_client_parse_header(line, "Sec-WebSocket-Accept"))) {
				free(accept_key);
				accept_key = value;
			}
			else if ((value = uwsc_client_parse_header(line, "Sec-WebSocket-Protocol"))) {
				free(protocol);
				protocol = value;
			}
		}

		line = strtok_r(NULL, "\n", &saveptr);
	}

	if (status != 101) {
		char errbuf[256];
		snprintf(errbuf, sizeof(errbuf), "HTTP upgrade failed: %d %s",
		         status, reason ? reason : "");
		uwsc_client_set_error(client, errbuf);
		goto cleanup;
	}

	if (!upgrade || strcasecmp(upgrade, "websocket") != 0) {
		uwsc_client_set_error(client, "Server did not upgrade to WebSocket");
		goto cleanup;
	}

	if (!connection || strcasestr(connection, "upgrade") == NULL) {
		uwsc_client_set_error(client, "Server did not send proper Connection header");
		goto cleanup;
	}

	if (!accept_key || !uwsc_client_verify_accept_key(client->ws_key, accept_key)) {
		uwsc_client_set_error(client, "Invalid WebSocket accept key");
		goto cleanup;
	}

	if (protocol) {
		free(client->selected_protocol);
		client->selected_protocol = xstrdup(protocol);
		uwsc_log_debug(NULL, "Selected WebSocket protocol: %s", protocol);
	}

	uwsc_log_debug(NULL, "WebSocket handshake completed successfully");
	result = 0;

cleanup:
	free(response_copy);
	free(reason);
	free(upgrade);
	free(connection);
	free(accept_key);
	free(protocol);

	return result;
}

static void
uwsc_client_http_timeout(struct uloop_timeout *utm)
{
	uwsc_client_t *client = container_of(utm, uwsc_client_t, conn.utm);

	/* Abort if uloop is shutting down */
	if (uloop_cancelling())
		return;

	uwsc_client_set_error(client, "HTTP upgrade timeout");
}

/* Bytes read together with the upgrade response are WebSocket frames; stash
 * them in conn->buf where uwsc_conn_recv() consumes them before the socket. */
static void
uwsc_client_stash_residue(uwsc_client_t *client, const char *data, size_t len)
{
	if (!len)
		return;

	memcpy(client->conn.buf.data, data, len);
	client->conn.buf.pos = client->conn.buf.data;
	client->conn.buf.end = client->conn.buf.data + len;
}

static void
uwsc_client_ws_enter(uwsc_client_t *client)
{
	client->conn.ufd.cb = uwsc_client_ws_cb;
	uwsc_client_set_state(client, UWSC_CLIENT_STATE_CONNECTED);

	client->conn.utm.cb = uwsc_client_ws_timeout;
	if (client->timeout_idle > 0)
		uloop_timeout_set(&client->conn.utm, client->timeout_idle);
	else
		uloop_timeout_cancel(&client->conn.utm);
	client->ping_timer.cb = uwsc_client_ping_cb;
	uloop_timeout_set(&client->ping_timer, client->ping_timeout);

	if (uwsc_ucode_on_connect(client))
		return;

	/* Frames already stashed in conn->buf raise no further socket events;
	 * process them now. Partial tails wait for the next socket read. The
	 * in_callback flag defers any disconnect-triggered destruction of the
	 * client while this loop still dereferences it. */
	client->in_callback = true;

	while (client->state == UWSC_CLIENT_STATE_CONNECTED &&
	       uwsc_client_ws_buffered_frame_complete(client))
		uwsc_client_ws_cb(&client->conn.ufd, ULOOP_READ);

	client->in_callback = false;
}

static void
uwsc_client_http_cb(struct uloop_fd *ufd, unsigned int events)
{
	uwsc_client_t *client = container_of(ufd, uwsc_client_t, conn.ufd);
	ssize_t received;
	char *end_of_headers;
	size_t space_left;

	/* Abort if uloop is shutting down */
	if (uloop_cancelling())
		return;

	uloop_timeout_cancel(&client->conn.utm);

	if (!(events & ULOOP_READ)) {
		uwsc_client_set_error(client, "Unexpected socket event during HTTP upgrade");
		return;
	}

	/* Calculate how much space is left in the buffer */
	space_left = sizeof(client->http_buffer) - client->http_buffer_len - 1;
	if (space_left == 0) {
		uwsc_client_set_error(client, "HTTP response too large");
		return;
	}

	/* Read into the buffer at the current position */
	received = uwsc_conn_recv(&client->conn,
	                      client->http_buffer + client->http_buffer_len,
	                      space_left);
	if (received < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			/* Re-arm the timeout and wait for more data */
			uloop_timeout_set(&client->conn.utm, client->timeout_connect);
			return;
		}

		char errbuf[256];
		snprintf(errbuf, sizeof(errbuf), "Failed to receive HTTP response: %s",
		         strerror(errno));
		uwsc_client_set_error(client, errbuf);
		return;
	}

	if (received == 0) {
		uwsc_client_set_error(client, "Connection closed during HTTP upgrade");
		return;
	}

	/* Update buffer length and null terminate */
	client->http_buffer_len += received;
	client->http_buffer[client->http_buffer_len] = '\0';

	/* Check if this might be a WebSocket frame instead of HTTP */
	if (client->http_buffer_len >= 2) {
		unsigned char *buf = (unsigned char *)client->http_buffer;

		/* Check if it starts with HTTP */
		if (strncmp(client->http_buffer, "HTTP/", 5) != 0 && (buf[0] & 0x80) == 0x80) {
			/* This looks like a WebSocket frame (FIN bit set) */
			if (buf[0] == 0x88) {
				/* It's a CLOSE frame */
				uwsc_client_set_error(client, "Server rejected connection");
				return;
			}

			/* Server went straight to WebSocket mode */
			uwsc_client_stash_residue(client, client->http_buffer,
			                          client->http_buffer_len);
			uwsc_client_ws_enter(client);
			return;
		}
	}

	/* Check if we have complete headers */
	end_of_headers = strstr(client->http_buffer, "\r\n\r\n");
	if (!end_of_headers) {
		/* Re-arm timeout and wait for more data */
		uloop_timeout_set(&client->conn.utm, client->timeout_connect);
		return;
	}

	if (uwsc_client_process_response(client, client->http_buffer) == 0) {
		const char *residue = end_of_headers + 4;

		uwsc_client_stash_residue(client, residue,
		                          client->http_buffer_len - (residue - client->http_buffer));
		uwsc_client_ws_enter(client);
	}
}

__hidden int
uwsc_client_http_upgrade(uwsc_client_t *client)
{
	if (!client)
		return -1;

	/* Reset HTTP buffer for new request */
	client->http_buffer_len = 0;

	uwsc_log_debug(NULL, "Sending WebSocket upgrade request to %s:%u%s",
	               client->host, client->port, client->path);

	if (uwsc_client_send_upgrade_request(client) != 0)
		return -1;

	client->conn.ufd.cb = uwsc_client_http_cb;
	uloop_fd_add(&client->conn.ufd, ULOOP_READ);

	client->conn.utm.cb = uwsc_client_http_timeout;
	uloop_timeout_set(&client->conn.utm, client->timeout_connect);

	uwsc_client_set_state(client, UWSC_CLIENT_STATE_WS_HANDSHAKE);
	return 0;
}
