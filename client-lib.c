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

#include "client-internal.h"
#include "log.h"
#include "ssl.h"

#ifndef NDEBUG
static const char *client_state_names[] = {
	[UWSC_CLIENT_STATE_DISCONNECTED] = "DISCONNECTED",
	[UWSC_CLIENT_STATE_DNS_RESOLVE] = "DNS_RESOLVE",
	[UWSC_CLIENT_STATE_TCP_CONNECT] = "TCP_CONNECT",
	[UWSC_CLIENT_STATE_SSL_HANDSHAKE] = "SSL_HANDSHAKE",
	[UWSC_CLIENT_STATE_HTTP_UPGRADE] = "HTTP_UPGRADE",
	[UWSC_CLIENT_STATE_WS_HANDSHAKE] = "WS_HANDSHAKE",
	[UWSC_CLIENT_STATE_CONNECTED] = "CONNECTED",
	[UWSC_CLIENT_STATE_CLOSING] = "CLOSING",
	[UWSC_CLIENT_STATE_ERROR] = "ERROR"
};
#endif

__hidden void
uwsc_client_set_state(uwsc_client_t *client, uwsc_client_state_t state)
{
	if (client->state != state) {
#ifndef NDEBUG
		uwsc_log_debug(NULL, "Client state: %s -> %s",
		               client_state_names[client->state],
		               client_state_names[state]);
#endif
		client->state = state;
	}
}

__hidden void
uwsc_client_set_error(uwsc_client_t *client, const char *error)
{
	uwsc_client_set_state(client, UWSC_CLIENT_STATE_ERROR);

	uwsc_ucode_on_error(client, error);
}

static void
uwsc_client_free_resources(uwsc_client_t *client)
{
	uwsc_ssl_free(&client->conn);

	if (client->conn.ufd.fd != -1) {
		uloop_fd_delete(&client->conn.ufd);
		close(client->conn.ufd.fd);
		client->conn.ufd.fd = -1;
	}

	uloop_timeout_cancel(&client->conn.utm);
	uloop_timeout_cancel(&client->ping_timer);
	uloop_timeout_cancel(&client->reconnect_timer);
	uloop_timeout_cancel(&client->connect_timer);

	/* Drop stashed upgrade residue so it cannot leak into a reconnect */
	uwsc_io_reset(&client->conn);

	free(client->url);
	free(client->host);
	free(client->path);
	free(client->ws_key);
	free(client->selected_protocol);
	free(client->ca_cert_path);
	free(client->user_agent);
	free(client->close_info.reason);
	free(client->fragment.buffer);

	if (client->protocols) {
		for (size_t i = 0; i < client->protocol_count; i++)
			free(client->protocols[i]);
		free(client->protocols);
	}

	client->url = client->host = client->path = NULL;
	client->ws_key = client->selected_protocol = NULL;
	client->ca_cert_path = client->user_agent = client->close_info.reason = NULL;
	client->protocols = NULL;
	client->protocol_count = 0;
	client->fragment.buffer = NULL;
	client->fragment.size = 0;
	client->fragment.capacity = 0;
	client->fragment.in_fragment = false;

	uwsc_client_ws_recv_reset(client);
}

uwsc_client_t *
uwsc_client_create(const uwsc_client_config_t *config)
{
	uwsc_client_t *client = uwsc_alloc_obj(uwsc_client_t);

	client->state = UWSC_CLIENT_STATE_DISCONNECTED;
	client->conn.ufd.fd = -1;

	uwsc_io_reset(&client->conn);
	uwsc_client_send_buffer_init(client);

	if (config) {
		client->timeout_connect = config->timeout_connect;
		client->timeout_idle = config->timeout_idle;
		client->ping_timeout = config->ping_timeout;
		client->reconnect_timeout = config->reconnect_timeout;
		client->ssl_verify = config->ssl_verify;

		if (config->ca_cert_path)
			client->ca_cert_path = xstrdup(config->ca_cert_path);

		if (config->user_agent)
			client->user_agent = xstrdup(config->user_agent);

		if (config->protocols && config->protocol_count > 0) {
			client->protocols = xalloc(config->protocol_count * sizeof(char *));
			client->protocol_count = config->protocol_count;

			for (size_t i = 0; i < config->protocol_count; i++)
				client->protocols[i] = xstrdup(config->protocols[i]);
		}
	}

	if (!client->timeout_connect)
		client->timeout_connect = 30000;

	/* timeout_idle of 0 disables the idle timer. The ucode binding applies
	 * its own 60s default when the caller omits the option, so an explicit
	 * 0 must not be rewritten here. */

	if (!client->ping_timeout)
		client->ping_timeout = 15000; /* 15 seconds default */

	if (!client->user_agent)
		client->user_agent = xstrdup("uwsc/1.0");

	return client;
}

void
uwsc_client_destroy(uwsc_client_t *client)
{
	if (!client)
		return;

	uwsc_client_free_resources(client);
	free(client);
}

int
uwsc_client_connect(uwsc_client_t *client, const char *url)
{
	if (!client || !url)
		return -1;

	if (client->state != UWSC_CLIENT_STATE_DISCONNECTED) {
		uwsc_client_set_error(client, "Client already connected or connecting");
		return -1;
	}

	/* Save configuration before cleanup */
	char **saved_protocols = client->protocols;
	size_t saved_protocol_count = client->protocol_count;
	char *saved_ca_cert_path = client->ca_cert_path;
	client->protocols = NULL;
	client->protocol_count = 0;
	client->ca_cert_path = NULL;

	uwsc_client_free_resources(client);

	/* Restore configuration */
	client->protocols = saved_protocols;
	client->protocol_count = saved_protocol_count;
	client->ca_cert_path = saved_ca_cert_path;

	client->url = xstrdup(url);

	if (uwsc_client_parse_url(url, &client->host, &client->port,
	                          &client->path, &client->use_ssl) != 0) {
		uwsc_client_set_error(client, "Invalid URL format");
		return -1;
	}

	uwsc_client_set_state(client, UWSC_CLIENT_STATE_DNS_RESOLVE);

	return uwsc_client_resolve_host(client);
}

int
uwsc_client_send(uwsc_client_t *client, const void *data, size_t len, bool binary)
{
	if (!client || !data || len == 0)
		return -1;

	if (client->state != UWSC_CLIENT_STATE_CONNECTED) {
		uwsc_client_set_error(client, "Client not connected");
		return -1;
	}

	if (binary)
		return uwsc_client_ws_send_binary(client, data, len);
	else
		return uwsc_client_ws_send_text(client, (const char *)data);
}

int
uwsc_client_close(uwsc_client_t *client, uint16_t code, const char *reason)
{
	if (!client)
		return -1;

	if (client->state == UWSC_CLIENT_STATE_DISCONNECTED ||
	    client->state == UWSC_CLIENT_STATE_CLOSING)
		return 0;

	client->close_info.code = code ? code : 1000;
	free(client->close_info.reason);
	client->close_info.reason = reason ? xstrdup(reason) : NULL;

	/* Send WebSocket close frame if connected */
	if (client->state == UWSC_CLIENT_STATE_CONNECTED) {
		uwsc_client_ws_send_close(client, client->close_info.code, client->close_info.reason);
	}

	uwsc_client_set_state(client, UWSC_CLIENT_STATE_CLOSING);
	uwsc_client_free_resources(client);
	uwsc_client_set_state(client, UWSC_CLIENT_STATE_DISCONNECTED);

	return 0;
}

uwsc_client_state_t
uwsc_client_get_state(uwsc_client_t *client)
{
	return client ? client->state : UWSC_CLIENT_STATE_ERROR;
}

const char *
uwsc_client_get_selected_protocol(uwsc_client_t *client)
{
	return client ? client->selected_protocol : NULL;
}
