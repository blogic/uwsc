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
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "client-internal.h"
#include "log.h"
#include "ssl.h"

static void uwsc_client_connect_timeout(struct uloop_timeout *utm);
static void uwsc_client_connect_cb(struct uloop_fd *ufd, unsigned int events);

static void
uwsc_client_setup_socket(uwsc_client_t *client, int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags != -1)
		fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	client->conn.ufd.fd = fd;
	client->conn.ufd.cb = uwsc_client_connect_cb;
	uloop_fd_add(&client->conn.ufd, ULOOP_WRITE);

	client->conn.utm.cb = uwsc_client_connect_timeout;
	uloop_timeout_set(&client->conn.utm, client->timeout_connect);
}

static void
uwsc_client_connect_timeout(struct uloop_timeout *utm)
{
	uwsc_client_t *client = container_of(utm, uwsc_client_t, conn.utm);

	/* Abort if uloop is shutting down */
	if (uloop_cancelling())
		return;

	uwsc_client_set_error(client, "Connection timeout");
}

static void
uwsc_client_connect_cb(struct uloop_fd *ufd, unsigned int events)
{
	uwsc_client_t *client = container_of(ufd, uwsc_client_t, conn.ufd);
	int error = 0;
	socklen_t len = sizeof(error);

	/* Abort if uloop is shutting down */
	if (uloop_cancelling())
		return;

	uloop_timeout_cancel(&client->conn.utm);

	if (!(events & ULOOP_WRITE)) {
		uwsc_client_set_error(client, "Unexpected socket event during connection");
		return;
	}

	if (getsockopt(client->conn.ufd.fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
		uloop_fd_delete(&client->conn.ufd);

		if (client->use_ssl) {
			uwsc_client_set_state(client, UWSC_CLIENT_STATE_SSL_HANDSHAKE);
			uwsc_client_ssl_handshake(client);
		}
		else {
			uwsc_client_set_state(client, UWSC_CLIENT_STATE_HTTP_UPGRADE);
			uwsc_client_http_upgrade(client);
		}
	}
	else {
		char errbuf[256];
		snprintf(errbuf, sizeof(errbuf), "Connection failed: %s",
		         error ? strerror(error) : "Unknown error");
		uwsc_client_set_error(client, errbuf);
	}
}

__hidden int
uwsc_client_resolve_host(uwsc_client_t *client)
{
	struct addrinfo hints = {0}, *result = NULL, *rp;
	char port_str[8];
	int ret, fd = -1;

	if (!client || !client->host)
		return -1;

	snprintf(port_str, sizeof(port_str), "%u", client->port);

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;

	ret = getaddrinfo(client->host, port_str, &hints, &result);
	if (ret != 0) {
		char errbuf[256];
		snprintf(errbuf, sizeof(errbuf), "DNS resolution failed: %s", gai_strerror(ret));
		uwsc_client_set_error(client, errbuf);
		return -1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd == -1)
			continue;

		memcpy(&client->sa_peer.unspec, rp->ai_addr, rp->ai_addrlen);

		uwsc_client_set_state(client, UWSC_CLIENT_STATE_TCP_CONNECT);

		ret = connect(fd, rp->ai_addr, rp->ai_addrlen);
		if (ret == 0) {
			/* Immediate connection */
			freeaddrinfo(result);
			client->conn.ufd.fd = fd;

			if (client->use_ssl) {
				uwsc_client_set_state(client, UWSC_CLIENT_STATE_SSL_HANDSHAKE);
				return uwsc_client_ssl_handshake(client);
			}
			else {
				uwsc_client_set_state(client, UWSC_CLIENT_STATE_HTTP_UPGRADE);
				return uwsc_client_http_upgrade(client);
			}
		}
		else if (errno == EINPROGRESS) {
			/* Async connection */
			freeaddrinfo(result);
			uwsc_client_setup_socket(client, fd);
			return 0;
		}

		close(fd);
		fd = -1;
	}

	freeaddrinfo(result);

	if (fd == -1) {
		char errbuf[256];
		snprintf(errbuf, sizeof(errbuf), "Connection failed: %s", strerror(errno));
		uwsc_client_set_error(client, errbuf);
		return -1;
	}

	return 0;
}

__hidden int
uwsc_client_tcp_connect(uwsc_client_t *client)
{
	return uwsc_client_resolve_host(client);
}

__hidden int
uwsc_client_ssl_handshake(uwsc_client_t *client)
{
	if (!client->use_ssl) {
		uwsc_client_set_state(client, UWSC_CLIENT_STATE_HTTP_UPGRADE);
		return uwsc_client_http_upgrade(client);
	}

	if (!uwsc_client_ssl_init(client)) {
		uwsc_client_set_error(client, "SSL initialization failed");
		return -1;
	}

	if (!uwsc_client_ssl_connect(client)) {
		uwsc_client_set_error(client, "SSL handshake failed");
		return -1;
	}

	uwsc_client_set_state(client, UWSC_CLIENT_STATE_HTTP_UPGRADE);
	return uwsc_client_http_upgrade(client);
}
