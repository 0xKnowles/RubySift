# RubySift

A desktop companion for [Ruby](https://github.com/0xKnowles/Ruby), the
ESP32-C3 RF telemetry sensor. RubySift decrypts Ruby's `.rub` SD-card logs
locally and visualizes ambient RF activity, nearby device clusters, and your
companion creature's state — all without ever writing the decryption key to
disk.

## Stack

- **Backend:** Go. Handles file I/O, AES-256-GCM decryption, and binary
  record parsing.
- **Frontend:** a minimal embedded static dashboard (vanilla HTML/CSS/JS,
  canvas-based charts), served by the same binary.
- **Communication:** the backend listens on `127.0.0.1` only — nothing
  leaves the machine.

## Running

```sh
go run . -addr 127.0.0.1:8787
```

Then open `http://127.0.0.1:8787`, point it at a `.rub` file, and enter
either a passphrase or a 64-character hex AES-256 key. The key is held only
in memory for the session and is discarded on `Close session` or process
exit — it is never persisted to disk.

## `.rub` file format

Ruby writes a sequence of fixed-width 44-byte frames:

```
[ 12-byte IV/nonce ][ 16-byte AES-256-GCM ciphertext ][ 16-byte auth tag ]
```

Each frame authenticates and decrypts to exactly one 16-byte plaintext
record:

| Offset      | Type         | Field                                                          |
|-------------|--------------|-----------------------------------------------------------------|
| `0x00-0x03` | `uint32_t`   | Epoch timestamp (LE) — time of observation, or runtime ticks    |
| `0x04`      | `uint8_t`    | Record type: `0x01` Wi-Fi handshake, `0x02` BLE beacon, `0x03` node catalog, `0x04` companion state |
| `0x05-0x0A` | `uint8_t[6]` | MAC address of the observed node                                 |
| `0x0B`      | `int8_t`     | RSSI (dBm)                                                       |
| `0x0C-0x0F` | `uint32_t`   | Frame control bits (channel/protocol/capabilities, LE)           |

Record type `0x04` (companion state) reuses the same 16-byte frame but
reinterprets the bytes after the type field as the companion creature's
state instead of a radio observation:

| Offset      | Type       | Field                                  |
|-------------|------------|------------------------------------------|
| `0x00-0x03` | `uint32_t` | Last-active epoch                        |
| `0x05`      | `uint8_t`  | Lifetime level                            |
| `0x06`      | `uint8_t`  | Mood (0-100)                              |
| `0x07`      | `uint8_t`  | Mood state enum (sleepy/curious/alert/content) |
| `0x08-0x0B` | `uint32_t` | Signals processed during the last run    |

> These offsets/enums for the companion block are RubySift's own convention
> for reading Ruby's "creature state" data — adjust `internal/parser/companion.go`
> if Ruby's firmware defines a different layout.

## Dashboard

- **Pulse Grid** — a 24-hour heatmap of ambient RF density by hour of day.
- **Signal Proximity** — nodes clustered and plotted by average RSSI, so
  background noise separates visually from devices that passed close by.
- **Companion** — a small pixel-art rendering of your Ruby companion's mood,
  level, and signal-processing activity from its last run.

## Layout

```
main.go                    entry point + embedded web assets
internal/cipher/           AES-256-GCM frame decryption
internal/parser/           binary record + companion-state decoding
internal/analytics/        pulse grid + proximity clustering
internal/server/           loopback HTTP API + in-memory session state
web/                       dashboard frontend (embedded into the binary)
```

## Testing

```sh
go test ./...
```
