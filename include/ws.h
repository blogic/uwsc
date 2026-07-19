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

#ifndef UWSC_WS_H
#define UWSC_WS_H

#include <stdint.h>

typedef enum {
	UWSC_OPCODE_CONTINUATION,
	UWSC_OPCODE_TEXT,
	UWSC_OPCODE_BINARY,
	UWSC_OPCODE_RESERVED_3,
	UWSC_OPCODE_RESERVED_4,
	UWSC_OPCODE_RESERVED_5,
	UWSC_OPCODE_RESERVED_6,
	UWSC_OPCODE_RESERVED_7,
	UWSC_OPCODE_CLOSE,
	UWSC_OPCODE_PING,
	UWSC_OPCODE_PONG,
	UWSC_OPCODE_RESERVED_11,
	UWSC_OPCODE_RESERVED_12,
	UWSC_OPCODE_RESERVED_13,
	UWSC_OPCODE_RESERVED_14,
	UWSC_OPCODE_RESERVED_15
} uwsc_ws_opcode_t;

typedef struct __attribute__((packed)) {
	uint8_t opcode:4;
	uint8_t rsv3:1;
	uint8_t rsv2:1;
	uint8_t rsv1:1;
	uint8_t fin:1;

	uint8_t len:7;
	uint8_t mask:1;
} uwsc_ws_frame_header_t;

#endif /* UWSC_WS_H */
