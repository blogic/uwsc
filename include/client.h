/*
 * Copyright (C) 2022 Jo-Philipp Wich <jo@mein.io>
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

#ifndef UWSC_CLIENT_H
#define UWSC_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <libubox/uloop.h>

#include "util.h"


typedef struct {
	uint8_t data[65536];  /* 64KB buffer for fragmented sends */
	uint8_t *pos, *end;
} uwsc_buffer_t;

typedef struct uwsc_connection {
	void *ssl;
	struct uloop_fd ufd;
	struct uloop_timeout utm;
	uwsc_buffer_t buf;
} uwsc_connection_t;

__hidden ssize_t uwsc_conn_pending(uwsc_connection_t *);
__hidden ssize_t uwsc_conn_recv(uwsc_connection_t *, void *, size_t);
__hidden ssize_t uwsc_conn_sendv(uwsc_connection_t *, struct iovec *, size_t);
__hidden ssize_t uwsc_conn_sendfile(uwsc_connection_t *, int, off_t *, size_t);

static inline void
uwsc_io_reset(uwsc_connection_t *conn)
{
	conn->buf.pos = conn->buf.data;
	conn->buf.end = conn->buf.pos;
}

#endif /* UWSC_CLIENT_H */
