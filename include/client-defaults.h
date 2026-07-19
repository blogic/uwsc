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
 * Default limits for the WebSocket client.
 * These can be overridden at compile time.
 */

#ifndef UWSC_CLIENT_DEFAULTS_H
#define UWSC_CLIENT_DEFAULTS_H

/* HTTP upgrade response buffer size
 * Most HTTP headers fit in 4KB, but some servers send large cookies/headers
 */
#ifndef UWSC_HTTP_BUFFER_SIZE
#define UWSC_HTTP_BUFFER_SIZE      4096
#endif

/* Maximum WebSocket frame size
 * 256KB default is reasonable for embedded systems
 * Can be increased for applications that need larger transfers
 */
#ifndef UWSC_MAX_FRAME_SIZE
#define UWSC_MAX_FRAME_SIZE        (256 * 1024)  /* 256KB */
#endif

/* Maximum size for text messages (may want smaller than binary)
 * JSON/text messages are typically smaller than binary data
 * Set to 16KB so that fragmented messages can fit in our 64KB buffer
 */
#ifndef UWSC_MAX_TEXT_FRAME_SIZE
#define UWSC_MAX_TEXT_FRAME_SIZE   (16 * 1024)   /* 16KB */
#endif

/* Maximum size for binary messages before fragmentation
 * Binary data can be larger than text
 */
#ifndef UWSC_MAX_BINARY_FRAME_SIZE
#define UWSC_MAX_BINARY_FRAME_SIZE (16 * 1024)  /* 16KB - same as text */
#endif

/* HTTP request buffer size for outgoing upgrade request
 * 2KB is plenty for WebSocket upgrade request
 */
#ifndef UWSC_HTTP_REQUEST_SIZE
#define UWSC_HTTP_REQUEST_SIZE     2048
#endif

/* Protocol negotiation header buffer
 * For Sec-WebSocket-Protocol header value
 */
#ifndef UWSC_PROTOCOL_BUFFER_SIZE
#define UWSC_PROTOCOL_BUFFER_SIZE  512
#endif

#endif /* UWSC_CLIENT_DEFAULTS_H */
