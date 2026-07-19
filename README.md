# RubySift

A desktop companion for [Ruby](https://github.com/0xKnowles/Ruby), the
ESP32-C3 RF telemetry sensor. RubySift decrypts Ruby's `.pclog` SD-card logs
locally and visualizes ambient RF activity and nearby device clusters,
without ever writing the decryption key to disk.

## Stack

- **Backend:** Go. Handles file I/O, AES-256-GCM decryption, and binary
  record parsing.
- **Frontend:** a minimal embedded static dashboard (vanilla HTML/CSS/JS,
  canvas-based charts), served by the same binary.
- **Communication:** the backend listens on `127.0.0.1` only — nothing
  leaves the machine.

## Getting a log onto your computer

Ruby has no USB or Wi-Fi transfer protocol. To get a log off the device:

1. Power the device off and pull the SD card.
2. Copy the encrypted log file(s) from `/.ruby/log/*.pclog` to your computer.
3. On the device, go to **Settings → Reveal log key** to get the 64-character
   hex AES-256 key for that file. (Ruby derives this key once at boot from
   its hardware TRNG + eFuse MAC — it's per-device, and the device never
   needs a key typed into it; its own on-device Log Viewer just uses the
   copy resident in RAM.)

RubySift is a GUI alternative to Ruby's own `scripts/decrypt_log.py --key
<hex> file.pclog` — same crypto, plus a dashboard.

## Running

```sh
go run . -addr 127.0.0.1:8787
```

Then open `http://127.0.0.1:8787`, point it at a `.pclog` file, and paste in
the 64-character hex key from Settings → Reveal log key (a passphrase is
also accepted and gets SHA-256'd into a key, but the device's own key is
what actually decrypts real Ruby logs). The key is held only in memory for
the session and is discarded on `Close session` or process exit.

## `.pclog` file format

This mirrors Ruby's firmware source (`lib/RubyLog/LogRecord.h` and
`EncryptedLog.cpp`). Every record is written as a fixed-width 70-byte
on-disk envelope (`kLogRecordEnvelopeSize`), so record N always starts at
byte `N * 70` — the format supports O(1) random access without a key, and
GCM's auth tag doubles as tamper/corruption detection:

```
[ 1B format version ][ 12B nonce ][ 2B ciphertext length (LE) ][ 39B ciphertext ][ 16B GCM tag ]
```

No AAD is used — only the plaintext payload is encrypted and authenticated;
the version/nonce/length header is read and trusted as-is.

Each envelope decrypts to a 39-byte `LogRecordPlaintext`:

| Offset      | Type          | Field         | Notes                                    |
|-------------|---------------|---------------|-------------------------------------------|
| `0x00-0x03` | `uint32_t`    | `unixTime`    | timestamp (LE)                            |
| `0x04`      | `uint8_t`     | `type`        | `0`=WifiAp, `1`=WifiClient, `2`=WifiHandshake, `3`=BleDevice |
| `0x05-0x0A` | `uint8_t[6]`  | `mac`         |                                            |
| `0x0B`      | `int8_t`      | `rssi`        | dBm                                       |
| `0x0C`      | `uint8_t`     | `extra`       | Wi-Fi channel, or BLE address type        |
| `0x0D-0x24` | `uint8_t[24]` | `label`       | SSID or BLE name (not NUL-terminated)     |
| `0x25`      | `uint8_t`     | `labelLen`    | length of `label` actually used           |
| `0x26`      | `uint8_t`     | `eapolMsgNum` | Wi-Fi handshake message number, 1-4       |

## Dashboard

- **Pulse Grid** — a 24-hour heatmap of ambient RF density by hour of day.
- **Signal Proximity** — nodes clustered and plotted by average RSSI, so
  background noise separates visually from devices that passed close by.
- **Nodes table** — every MAC seen, with its most recent SSID/BLE label,
  sighting count, and RSSI stats.

## Layout

```
main.go                    entry point + embedded web assets
internal/cipher/           AES-256-GCM envelope decryption
internal/parser/           LogRecordPlaintext decoding
internal/analytics/        pulse grid + proximity clustering
internal/server/           loopback HTTP API + in-memory session state
web/                       dashboard frontend (embedded into the binary)
```

## Testing

```sh
go test ./...
```
