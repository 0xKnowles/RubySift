package parser

import (
	"encoding/binary"
	"fmt"
)

// CompanionState reinterprets a RecordCompanionState (0x04) 16-byte block.
// It shares the fixed-width frame used by every other record type, but the
// bytes after the record-type field carry the Ruby companion's creature
// state instead of a radio observation:
//
//	Offset   Type        Field
//	0x00-03  uint32_t    last active epoch
//	0x04     uint8_t     record type (0x04)
//	0x05     uint8_t     lifetime level
//	0x06     uint8_t     mood (0-100)
//	0x07     uint8_t     mood state enum
//	0x08-0B  uint32_t    signals processed this run
//	0x0C-0F  —           reserved
type CompanionState struct {
	LastActive       uint32    `json:"last_active"`
	Level            uint8     `json:"level"`
	Mood             uint8     `json:"mood"`
	MoodState        MoodState `json:"mood_state"`
	MoodStateName    string    `json:"mood_state_name"`
	SignalsProcessed uint32    `json:"signals_processed"`
}

type MoodState uint8

const (
	MoodSleepy  MoodState = 0
	MoodCurious MoodState = 1
	MoodAlert   MoodState = 2
	MoodContent MoodState = 3
)

func (m MoodState) String() string {
	switch m {
	case MoodSleepy:
		return "sleepy"
	case MoodCurious:
		return "curious"
	case MoodAlert:
		return "alert"
	case MoodContent:
		return "content"
	default:
		return "unknown"
	}
}

// DecodeCompanion unpacks a 16-byte companion-state record.
func DecodeCompanion(b []byte) (CompanionState, error) {
	if len(b) != Size {
		return CompanionState{}, fmt.Errorf("parser: companion record must be %d bytes, got %d", Size, len(b))
	}
	ms := MoodState(b[0x07])
	return CompanionState{
		LastActive:       binary.LittleEndian.Uint32(b[0x00:0x04]),
		Level:            b[0x05],
		Mood:             b[0x06],
		MoodState:        ms,
		MoodStateName:    ms.String(),
		SignalsProcessed: binary.LittleEndian.Uint32(b[0x08:0x0C]),
	}, nil
}
