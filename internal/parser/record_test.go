package parser

import (
	"encoding/binary"
	"testing"
)

func buildRecord(ts uint32, rt RecordType, mac [6]byte, rssi int8, extra uint8, label string, eapol uint8) []byte {
	b := make([]byte, Size)
	binary.LittleEndian.PutUint32(b[offUnixTime:offUnixTime+4], ts)
	b[offType] = byte(rt)
	copy(b[offMAC:offMAC+6], mac[:])
	b[offRSSI] = byte(rssi)
	b[offExtra] = extra
	n := copy(b[offLabel:offLabel+labelLen], label)
	b[offLabelLen] = byte(n)
	b[offEapolMsgNum] = eapol
	return b
}

func TestDecodeWiFiHandshake(t *testing.T) {
	mac := [6]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}
	raw := buildRecord(1_700_000_000, RecordWiFiHandshake, mac, -42, 6, "MyWiFi", 2)

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
	if rec.Extra != 6 {
		t.Errorf("extra (channel) = %d", rec.Extra)
	}
	if rec.Label != "MyWiFi" {
		t.Errorf("label = %q", rec.Label)
	}
	if rec.EapolMsgNum != 2 {
		t.Errorf("eapol msg num = %d", rec.EapolMsgNum)
	}
}

func TestDecodeBLEDevice(t *testing.T) {
	mac := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	raw := buildRecord(0, RecordBLEDevice, mac, -80, 1, "Pixel Buds", 0)

	rec, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.TypeName != "ble_device" {
		t.Errorf("type name = %s", rec.TypeName)
	}
	if rec.Label != "Pixel Buds" {
		t.Errorf("label = %q", rec.Label)
	}
}

func TestDecodeUnknownType(t *testing.T) {
	raw := buildRecord(0, RecordType(0x7F), [6]byte{}, 0, 0, "", 0)
	rec, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if rec.TypeName != "unknown(0x7f)" {
		t.Errorf("type name = %s", rec.TypeName)
	}
}

func TestDecodeTruncatesOversizedLabelLen(t *testing.T) {
	raw := buildRecord(0, RecordWiFiAP, [6]byte{}, 0, 0, "short", 0)
	raw[offLabelLen] = 250 // corrupt/oversized labelLen must not overrun the 24-byte label field
	rec, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Label) > labelLen {
		t.Errorf("label length = %d, want <= %d", len(rec.Label), labelLen)
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
