// Package parser unpacks the fixed-width 39-byte LogRecordPlaintext
// records Ruby's firmware writes to the SD card, matching the struct in
// lib/RubyLog/LogRecord.h:
//
//	Offset   Type          Field
//	0x00-03  uint32_t      unixTime (LE)
//	0x04     uint8_t       type (0=WifiAp, 1=WifiClient, 2=WifiHandshake, 3=BleDevice)
//	0x05-0A  uint8_t[6]    mac
//	0x0B     int8_t        rssi (dBm)
//	0x0C     uint8_t       extra (WiFi channel, or BLE address type)
//	0x0D-24  uint8_t[24]   label (SSID or BLE name, not necessarily NUL-terminated)
//	0x25     uint8_t       labelLen
//	0x26     uint8_t       eapolMsgNum (WiFi handshake message number, 1-4)
package parser

import (
	"encoding/binary"
	"fmt"
	"net"
)

// RecordType identifies what kind of observation a record holds.
type RecordType uint8

const (
	RecordWiFiAP        RecordType = 0
	RecordWiFiClient    RecordType = 1
	RecordWiFiHandshake RecordType = 2
	RecordBLEDevice     RecordType = 3
)

func (t RecordType) String() string {
	switch t {
	case RecordWiFiAP:
		return "wifi_ap"
	case RecordWiFiClient:
		return "wifi_client"
	case RecordWiFiHandshake:
		return "wifi_handshake"
	case RecordBLEDevice:
		return "ble_device"
	default:
		return fmt.Sprintf("unknown(0x%02x)", uint8(t))
	}
}

const Size = 39

const (
	offUnixTime    = 0x00
	offType        = 0x04
	offMAC         = 0x05
	offRSSI        = 0x0B
	offExtra       = 0x0C
	offLabel       = 0x0D
	labelLen       = 24
	offLabelLen    = offLabel + labelLen // 0x25
	offEapolMsgNum = offLabelLen + 1     // 0x26
)

// Record is the decoded form of one 39-byte plaintext telemetry block.
type Record struct {
	Timestamp   uint32     `json:"timestamp"`
	Type        RecordType `json:"type"`
	TypeName    string     `json:"type_name"`
	MAC         string     `json:"mac"`
	RSSI        int8       `json:"rssi"`
	Extra       uint8      `json:"extra"` // WiFi channel, or BLE address type
	Label       string     `json:"label"` // SSID or BLE name
	EapolMsgNum uint8      `json:"eapol_msg_num,omitempty"`
}

// Decode unpacks a 39-byte plaintext record into a Record.
func Decode(b []byte) (Record, error) {
	if len(b) != Size {
		return Record{}, fmt.Errorf("parser: record must be %d bytes, got %d", Size, len(b))
	}
	rt := RecordType(b[offType])
	mac := net.HardwareAddr(b[offMAC : offMAC+6])

	n := int(b[offLabelLen])
	if n > labelLen {
		n = labelLen
	}

	return Record{
		Timestamp:   binary.LittleEndian.Uint32(b[offUnixTime : offUnixTime+4]),
		Type:        rt,
		TypeName:    rt.String(),
		MAC:         mac.String(),
		RSSI:        int8(b[offRSSI]),
		Extra:       b[offExtra],
		Label:       string(b[offLabel : offLabel+n]),
		EapolMsgNum: b[offEapolMsgNum],
	}, nil
}
