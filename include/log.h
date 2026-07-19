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

#ifndef UWSC_LOG_H
#define UWSC_LOG_H

#include "util.h"


typedef enum {
	UWSC_PRIO_DBG,
	UWSC_PRIO_INFO,
	UWSC_PRIO_WARN,
	UWSC_PRIO_ERR
} uwsc_log_priority_t;

typedef enum {
	UWSC_LOG_GLOBAL,
	UWSC_LOG_HTTP,
	UWSC_LOG_WS,
	UWSC_LOG_SSL,
} uwsc_log_channel_t;

extern uwsc_log_priority_t uwsc_logging_priority;
extern unsigned int uwsc_logging_channels;

struct uwsc_client;

__hidden __attribute__((format(printf, 4, 0))) void
uwsc_log(uwsc_log_priority_t, uwsc_log_channel_t, struct uwsc_client *, const char *, ...);


#ifdef NDEBUG
# define uwsc_log_debug(...)
#else
# define uwsc_log_debug(...) uwsc_log(UWSC_PRIO_DBG, UWSC_LOG_GLOBAL, __VA_ARGS__)
#endif

#define uwsc_log_info(...) uwsc_log(UWSC_PRIO_INFO, UWSC_LOG_GLOBAL, __VA_ARGS__)
#define uwsc_log_warn(...) uwsc_log(UWSC_PRIO_WARN, UWSC_LOG_GLOBAL, __VA_ARGS__)
#define uwsc_log_err(...) uwsc_log(UWSC_PRIO_ERR, UWSC_LOG_GLOBAL, __VA_ARGS__)

#endif /* UWSC_LOG_H */
