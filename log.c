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

#include <stdio.h>
#include <stdarg.h>

#include <sys/time.h>
#include <arpa/inet.h>

#include "client-internal.h"
#include "log.h"


uwsc_log_priority_t uwsc_logging_priority = UWSC_PRIO_INFO;
unsigned int uwsc_logging_channels = -1;

__hidden __attribute__((format(printf, 4, 0))) void
uwsc_log(uwsc_log_priority_t prio, uwsc_log_channel_t chan, uwsc_client_t *cl, const char *fmt, ...)
{
	char buf[INET6_ADDRSTRLEN + 2];
	struct timeval tv = { 0 };
	va_list ap;

	if (prio < uwsc_logging_priority)
		return;

	if (!(uwsc_logging_channels & (1 << chan)))
		return;

	gettimeofday(&tv, NULL);

	fprintf(stderr, "[%010ld.%04ld] ",
		(long)tv.tv_sec, (long)tv.tv_usec / 1000);

	if (cl) {
		if (cl->sa_peer.unspec.sa_family == AF_INET6)
			fprintf(stderr, "([%s]:%hu) ",
				inet_ntop(AF_INET6, &cl->sa_peer.in6.sin6_addr, buf, sizeof(buf)),
				ntohs(cl->sa_peer.in6.sin6_port));
		else
			fprintf(stderr, "(%s:%hu) ",
				inet_ntop(AF_INET, &cl->sa_peer.in.sin_addr, buf, sizeof(buf)),
				ntohs(cl->sa_peer.in.sin_port));
	}

	switch (prio) {
	case UWSC_PRIO_DBG:
		fprintf(stderr, "[D] ");
		break;

	case UWSC_PRIO_INFO:
		fprintf(stderr, "[I] ");
		break;

	case UWSC_PRIO_WARN:
		fprintf(stderr, "[W] ");
		break;

	case UWSC_PRIO_ERR:
		fprintf(stderr, "[E] ");
		break;
	}

	switch (chan) {
	case UWSC_LOG_GLOBAL:
		break;

	case UWSC_LOG_HTTP:
		fprintf(stderr, "[HTTP] ");
		break;

	case UWSC_LOG_WS:
		fprintf(stderr, "[WS] ");
		break;

	case UWSC_LOG_SSL:
		fprintf(stderr, "[SSL] ");
		break;
	}

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");
}
