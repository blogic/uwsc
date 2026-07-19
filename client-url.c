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
#include <ctype.h>

#include "client-internal.h"
#include "util.h"

static bool
is_valid_hostname_char(char c)
{
	return isalnum(c) || c == '-' || c == '.' || c == '_';
}

static bool
is_ipv6_address(const char *host)
{
	return strchr(host, ':') != NULL;
}

__hidden int
uwsc_client_parse_url(const char *url, char **host, uint16_t *port,
                      char **path, bool *use_ssl)
{
	const char *p, *host_start, *host_end, *port_start, *path_start;
	char *end;
	long port_num;
	size_t host_len;
	bool ipv6 = false;

	if (!url || !host || !port || !path || !use_ssl)
		return -1;

	*host = NULL;
	*port = 0;
	*path = NULL;
	*use_ssl = false;

	p = url;

	if (strncmp(p, "ws://", 5) == 0) {
		*use_ssl = false;
		*port = 80;
		p += 5;
	}
	else if (strncmp(p, "wss://", 6) == 0) {
		*use_ssl = true;
		*port = 443;
		p += 6;
	}
	else {
		return -1;
	}

	host_start = p;

	if (*p == '[') {
		ipv6 = true;
		host_start = ++p;

		while (*p && *p != ']')
			p++;

		if (*p != ']')
			return -1;

		host_end = p++;
	}
	else {
		while (*p && *p != ':' && *p != '/' && is_valid_hostname_char(*p))
			p++;

		host_end = p;
	}

	host_len = host_end - host_start;
	if (host_len == 0 || host_len > 253)
		return -1;

	*host = xalloc(host_len + 1);
	memcpy(*host, host_start, host_len);
	(*host)[host_len] = '\0';

	if (!ipv6 && is_ipv6_address(*host)) {
		free(*host);
		*host = NULL;
		return -1;
	}

	if (*p == ':') {
		port_start = ++p;

		while (*p && isdigit(*p))
			p++;

		if (p == port_start || *p == ':') {
			free(*host);
			*host = NULL;
			return -1;
		}

		port_num = strtol(port_start, &end, 10);
		if (end != p || port_num < 1 || port_num > 65535) {
			free(*host);
			*host = NULL;
			return -1;
		}

		*port = (uint16_t)port_num;
	}

	if (*p == '/') {
		path_start = p;
	}
	else if (*p == '\0') {
		path_start = "/";
	}
	else {
		free(*host);
		*host = NULL;
		return -1;
	}

	*path = xstrdup(path_start);

	return 0;
}
