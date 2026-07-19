# uwsc - WebSocket client module for ucode

## Overview

uwsc provides WebSocket client functionality for ucode scripts as a loadable
module. It supports secure WebSocket connections (wss://), message
fragmentation, custom CA certificates and automatic reconnects. The wss://
transport is built on OpenSSL.

The code originates from the client half of the uwsd tree and is maintained
here as a standalone project. All symbols carry a `uwsc_` / `UWSC_` prefix so
the module can coexist with uwsd in the same process.

## Building

```bash
cmake -B build
make -C build
```

Dependencies: libubox, libucode, OpenSSL (libssl, libcrypto).

Install with `make -C build install`; the module is placed in `lib/ucode/`
relative to the install prefix.

## ucode API

### Import the Module

```javascript
import * as ws from 'uwsc';
```

### Functions

#### ws.connect(url, options)

Establishes a WebSocket connection to the specified URL.

**Parameters:**
- `url` (string): WebSocket URL (ws:// or wss://)
- `options` (object, optional):
  - `connection_timeout` (number): Connection timeout in milliseconds (default: 30000)
  - `ping_timeout` (number): Ping interval in milliseconds (default: 15000)
  - `reconnect_timeout` (number): Reconnect interval in milliseconds (default: 5000)
  - `ssl_verify` (bool): Verify SSL certificates (default: true)
  - `ca_cert` (string): Path to custom CA certificate for self-signed servers
  - `protocol` (string): WebSocket subprotocol to negotiate
  - `user_agent` (string): User-Agent header (default: "uwsc/1.0")
  - `on_connect` (function): Called when connection is established
  - `on_reconnect` (function): Called when connection is re-established after disconnect
  - `on_disconnect` (function): Called when connection is closed
  - `on_error` (function): Called on errors with error message
  - `on_recv` (function): Called when message is received with message object

**Returns:** Connection object or null on failure

**Message object structure:**
```javascript
{
    data: "message content",  // The actual message data
    binary: false             // true for binary, false for text
}
```

#### connection.send(data, binary)

Sends a message through the WebSocket connection.

**Parameters:**
- `data` (string): Message to send
- `binary` (bool, optional): Send as binary frame (default: false for text)

**Returns:** true on success, false on failure

**Note:** Large messages (>16KB) are automatically fragmented into smaller chunks.

#### connection.close(code, reason)

Closes the WebSocket connection gracefully.

**Parameters:**
- `code` (number, optional): Close code (default: 1000)
- `reason` (string, optional): Close reason

**Returns:** true on success, false on failure

#### connection.state()

Gets the current connection state.

**Returns:** String state: "disconnected", "pending", "resolving", "connecting", "ssl_handshake", "upgrading", "handshake", "connected", "closing", "error", or "unknown"

#### connection.receive()

Synchronously receives a message (blocking operation).

**Returns:** Message object or null if no message available

#### connection.is_connected()

Checks if connection is in connected state.

**Returns:** true if connected, false otherwise

## Examples

### Basic Echo Client

```javascript
#!/usr/bin/env ucode

import * as ws from 'uwsc';
import * as uloop from 'uloop';

uloop.init();

let conn = ws.connect("wss://echo.websocket.org/", {
    on_connect: function(conn) {
        print("Connected!\n");
        conn.send("Hello, WebSocket!");
    },

    on_recv: function(conn, message) {
        printf("Received: %s\n", message.data);
        conn.close(1000, "Done");
    },

    on_disconnect: function(conn) {
        print("Disconnected\n");
        uloop.end();
    },

    on_error: function(conn, error) {
        printf("Error: %s\n", error);
        uloop.end();
    }
});

if (conn) {
    uloop.run();
}
```

### Self-Signed Certificate Support

```javascript
let conn = ws.connect("wss://192.168.1.1:8443/ws", {
    ca_cert: "/path/to/server-ca.pem",
    ssl_verify: false,  // Skip hostname verification for self-signed
    on_connect: function(conn) {
        print("Connected to self-signed server\n");
    }
});
```

### Binary Message Handling

```javascript
let conn = ws.connect(url, {
    on_recv: function(conn, message) {
        if (message.binary) {
            printf("Binary message (%d bytes)\n", length(message.data));
            // Process binary data
        } else {
            printf("Text message: %s\n", message.data);
        }
    }
});

// Send binary data
let binary_data = "...";  // Binary string
conn.send(binary_data, true);
```

### Protocol Negotiation

```javascript
let conn = ws.connect(url, {
    protocol: "chat",
    on_connect: function(conn) {
        print("Connected with protocol negotiation\n");
        // Note: Negotiated protocol information not currently accessible via API
    }
});
```
