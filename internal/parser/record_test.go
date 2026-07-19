package parser

import (
	"encoding/binary"
	"testing"
)

func buildRecord(ts uint32, rt RecordType, mac [6]byte, rssi int8, frameCtrl uint32) []byte {
	b := make([]byte, Size)
	binary.LittleEndian.PutUint32(b[0x00:0x04], ts)
	b[0x04] = byte(rt)
	copy(b[0x05:0x0B], mac[:])
	b[0x0B] = byte(rssi)
	binary.LittleEndian.PutUint32(b[0x0C:0x10], frameCtrl)
	return b
}

func TestDecodeWiFiHandshake(t *testing.T) {
	mac := [6]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}
	raw := buildRecord(1_700_000_000, RecordWiFiHandshake, mac, -42, 0x0000FFAA)

	rec, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Timestamp != 1_700_000_000 {
		t.Errorf("timestamp = %d", rec.Timestamp)
	}
	if rec.Type != RecordWiFiHandshake || rec.TypeName != "wifi_handshake" {
		t.Errorf("type = %v/%s", rec.Type, rec.TypeName)
	}
	if rec.MAC != "de:ad:be:ef:00:01" {
		t.Errorf("mac = %s", rec.MAC)
	}
	if rec.RSSI != -42 {
		t.Errorf("rssi = %d", rec.RSSI)
	}
	if rec.FrameCtrl != 0x0000FFAA {
		t.Errorf("frame ctrl = %x", rec.FrameCtrl)
	}
}

func TestDecodeUnknownType(t *testing.T) {
	raw := buildRecord(0, RecordType(0x7F), [6]byte{}, 0, 0)
	rec, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.TypeName != "unknown(0x7f)" {
		t.Errorf("type name = %s", rec.TypeName)
	}
}

func TestDecodeRejectsWrongSize(t *testing.T) {
	if _, err := Decode(make([]byte, Size-1)); err == nil {
		t.Fatal("expected error for short record")
	}
	if _, err := Decode(make([]byte, Size+1)); err == nil {
		t.Fatal("expected error for long record")
	}
}
