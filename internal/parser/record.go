// Package parser unpacks the fixed-width 16-byte plaintext records that
// Ruby's firmware writes to the SD card, per the following C-struct layout:
//
//	Offset   Type        Field
//	0x00-03  uint32_t    epoch timestamp (LE)
//	0x04     uint8_t     record type
//	0x05-0A  uint8_t[6]  MAC address
//	0x0B     int8_t      RSSI (dBm)
//	0x0C-0F  uint32_t    frame control bits (LE)
package parser

import (
	"encoding/binary"
	"fmt"
	"net"
)

// RecordType identifies what kind of observation a record holds.
type RecordType uint8

const (
	RecordWiFiHandshake  RecordType = 0x01
	RecordBLEBeacon      RecordType = 0x02
	RecordNodeCatalog    RecordType = 0x03
	RecordCompanionState RecordType = 0x04
)

func (t RecordType) String() string {
	switch t {
	case RecordWiFiHandshake:
		return "wifi_handshake"
	case RecordBLEBeacon:
		return "ble_beacon"
	case RecordNodeCatalog:
		return "node_catalog"
	case RecordCompanionState:
		return "companion_state"
	default:
		return fmt.Sprintf("unknown(0x%02x)", uint8(t))
	}
}

const Size = 16

// Record is the decoded form of one 16-byte plaintext telemetry block.
type Record struct {
	Timestamp uint32     `json:"timestamp"`
	Type      RecordType `json:"type"`
	TypeName  string     `json:"type_name"`
	MAC       string     `json:"mac"`
	RSSI      int8       `json:"rssi"`
	FrameCtrl uint32     `json:"frame_control"`
}

// Decode unpacks a 16-byte plaintext record into a Record.
func Decode(b []byte) (Record, error) {
	if len(b) != Size {
		return Record{}, fmt.Errorf("parser: record must be %d bytes, got %d", Size, len(b))
	}
	rt := RecordType(b[0x04])
	mac := net.HardwareAddr(b[0x05:0x0B])
	return Record{
		Timestamp: binary.LittleEndian.Uint32(b[0x00:0x04]),
		Type:      rt,
		TypeName:  rt.String(),
		MAC:       mac.String(),
		RSSI:      int8(b[0x0B]),
		FrameCtrl: binary.LittleEndian.Uint32(b[0x0C:0x10]),
	}, nil
}
