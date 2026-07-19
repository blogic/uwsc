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
 *
 * WebSocket client send buffering, handles partial sends when the
 * socket would block.
 */

#include <string.h>
#include <errno.h>
#include "client-internal.h"
#include "client-defaults.h"
#include "log.h"

__hidden void
uwsc_client_send_buffer_init(uwsc_client_t *client)
{
	client->send_buf.pos = client->send_buf.data;
	client->send_buf.end = client->send_buf.data;
}

__hidden size_t
uwsc_client_send_buffer_space(uwsc_client_t *client)
{
	return sizeof(client->send_buf.data) - (client->send_buf.end - client->send_buf.data);
}

__hidden size_t
uwsc_client_send_buffer_pending(uwsc_client_t *client)
{
	return client->send_buf.end - client->send_buf.pos;
}

__hidden int
uwsc_client_send_buffer_append(uwsc_client_t *client, const void *data, size_t len)
{
	size_t space = uwsc_client_send_buffer_space(client);

	if (len > space) {
		uwsc_log_err(NULL, "Send buffer full: need %zu bytes, have %zu space", len, space);
		return -1;
	}

	memcpy(client->send_buf.end, data, len);
	client->send_buf.end += len;

	/* Enable write notification to flush buffer when socket is writable */
	if (client->conn.ufd.fd >= 0) {
		uloop_fd_add(&client->conn.ufd, ULOOP_READ | ULOOP_WRITE);
	}

	return 0;
}

__hidden int
uwsc_client_send_buffer_flush(uwsc_client_t *client)
{
	size_t pending = uwsc_client_send_buffer_pending(client);
	ssize_t sent;

	if (pending == 0)
		return 0;

	struct iovec iov = {
		.iov_base = client->send_buf.pos,
		.iov_len = pending
	};

	sent = uwsc_conn_sendv(&client->conn, &iov, 1);

	if (sent < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0; /* Will retry later */
		return -1;
	}

	client->send_buf.pos += sent;

	/* If buffer is now empty, reset pointers */
	if (client->send_buf.pos >= client->send_buf.end) {
		client->send_buf.pos = client->send_buf.data;
		client->send_buf.end = client->send_buf.data;
	}
	/* If we've consumed a significant portion, compact the buffer */
	else if ((size_t)(client->send_buf.pos - client->send_buf.data) > sizeof(client->send_buf.data) / 2) {
		size_t remaining = client->send_buf.end - client->send_buf.pos;
		memmove(client->send_buf.data, client->send_buf.pos, remaining);
		client->send_buf.pos = client->send_buf.data;
		client->send_buf.end = client->send_buf.data + remaining;
	}

	return (pending == (size_t)sent) ? 0 : 1; /* 1 = partial send */
}

__hidden int
uwsc_client_send_buffered(uwsc_client_t *client, const void *data, size_t len)
{
	ssize_t sent;

	/* First, try to flush any pending data */
	if (uwsc_client_send_buffer_pending(client) > 0) {
		if (uwsc_client_send_buffer_flush(client) < 0)
			return -1;

		/* If buffer still has data, we must buffer this new data too */
		if (uwsc_client_send_buffer_pending(client) > 0) {
			return uwsc_client_send_buffer_append(client, data, len);
		}
	}

	/* Try to send directly */
	struct iovec iov = {
		.iov_base = (void *)data,
		.iov_len = len
	};

	sent = uwsc_conn_sendv(&client->conn, &iov, 1);

	if (sent < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			/* Buffer the data for later */
			return uwsc_client_send_buffer_append(client, data, len);
		}
		return -1;
	}

	/* Partial send - buffer the remainder */
	if ((size_t)sent < len) {
		return uwsc_client_send_buffer_append(client,
		                                     (const uint8_t *)data + sent,
		                                     len - sent);
	}

	return 0;
}

__hidden void
uwsc_client_send_buffer_clear(uwsc_client_t *client)
{
	client->send_buf.pos = client->send_buf.data;
	client->send_buf.end = client->send_buf.data;
}
