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

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/sendfile.h>
#include <sys/ioctl.h>

#include "client-internal.h"
#include "ssl.h"

/* Bytes read together with the HTTP upgrade response are stashed in
 * conn->buf (see uwsc_client_http_cb) and must be consumed before the
 * socket is read again. */
static size_t
conn_buffer_take(uwsc_connection_t *conn, void *data, size_t len)
{
	size_t avail = conn->buf.end - conn->buf.pos;
	size_t take = (len < avail) ? len : avail;

	if (!take)
		return 0;

	memcpy(data, conn->buf.pos, take);
	conn->buf.pos += take;

	if (conn->buf.pos == conn->buf.end)
		uwsc_io_reset(conn);

	return take;
}

__hidden ssize_t
uwsc_conn_pending(uwsc_connection_t *conn)
{
	size_t buffered = conn->buf.end - conn->buf.pos;
	int pending;

	if (conn->ssl)
		return buffered + uwsc_ssl_pending(conn);

	if (ioctl(conn->ufd.fd, FIONREAD, &pending) == -1)
		return buffered ? (ssize_t)buffered : -1;

	return buffered + pending;
}

__hidden ssize_t
uwsc_conn_recv(uwsc_connection_t *conn, void *data, size_t len)
{
	size_t took = conn_buffer_take(conn, data, len);
	ssize_t ret;

	if (took == len)
		return took;

	if (conn->ssl)
		ret = uwsc_ssl_recv(conn, (uint8_t *)data + took, len - took);
	else
		ret = read(conn->ufd.fd, (uint8_t *)data + took, len - took);

	if (ret < 0)
		return took ? (ssize_t)took : ret;

	return took + ret;
}

__hidden ssize_t
uwsc_conn_sendv(uwsc_connection_t *conn, struct iovec *iov, size_t len)
{
	if (conn->ssl)
		return uwsc_ssl_sendv(conn, iov, len);

	return writev(conn->ufd.fd, iov, len);
}

__hidden ssize_t
uwsc_conn_sendfile(uwsc_connection_t *conn, int in_fd, off_t *offset, size_t count)
{
	if (conn->ssl) {
		errno = ENOSYS;
		return -1;
	}

	return sendfile(conn->ufd.fd, in_fd, offset, count);
}
