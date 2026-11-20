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

#ifndef UWSC_SSL_H
#define UWSC_SSL_H

#include <sys/uio.h>
#include <sys/types.h>

#include "util.h"


struct uwsc_connection;
struct uwsc_client;

__hidden bool uwsc_ssl_init_client_ctx(void);
__hidden void *uwsc_ssl_create_client(struct uwsc_client *client);
__hidden int uwsc_ssl_connect(struct uwsc_connection *);
__hidden void uwsc_ssl_free(struct uwsc_connection *);

__hidden ssize_t uwsc_ssl_pending(struct uwsc_connection *);
__hidden ssize_t uwsc_ssl_recv(struct uwsc_connection *, void *, size_t);
__hidden ssize_t uwsc_ssl_sendv(struct uwsc_connection *, struct iovec *, size_t);
__hidden ssize_t uwsc_ssl_close(struct uwsc_connection *);

#endif /* UWSC_SSL_H */
