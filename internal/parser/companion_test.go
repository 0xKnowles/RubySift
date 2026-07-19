package parser

import (
	"encoding/binary"
	"testing"
)

func TestDecodeCompanion(t *testing.T) {
	b := make([]byte, Size)
	binary.LittleEndian.PutUint32(b[0x00:0x04], 1_700_000_000)
	b[0x04] = byte(RecordCompanionState)
	b[0x05] = 12                // level
	b[0x06] = 87                // mood
	b[0x07] = byte(MoodContent) // mood state
	binary.LittleEndian.PutUint32(b[0x08:0x0C], 4321)

	cs, err := DecodeCompanion(b)
	if err != nil {
		t.Fatal(err)
	}
	if cs.LastActive != 1_700_000_000 {
		t.Errorf("last active = %d", cs.LastActive)
	}
	if cs.Level != 12 {
		t.Errorf("level = %d", cs.Level)
	}
	if cs.Mood != 87 {
		t.Errorf("mood = %d", cs.Mood)
	}
	if cs.MoodState != MoodContent || cs.MoodStateName != "content" {
		t.Errorf("mood state = %v/%s", cs.MoodState, cs.MoodStateName)
	}
	if cs.SignalsProcessed != 4321 {
		t.Errorf("signals processed = %d", cs.SignalsProcessed)
	}
}

func TestDecodeCompanionRejectsWrongSize(t *testing.T) {
	if _, err := DecodeCompanion(make([]byte, Size-1)); err == nil {
		t.Fatal("expected error for short record")
	}
}
