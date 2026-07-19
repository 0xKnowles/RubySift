// Package usbdevice talks to a Ruby device directly over its USB-CDC serial port, using the
// framed protocol implemented by UsbTransferActivity in the firmware
// (src/activities/usbtransfer/UsbTransferProtocol.h — the two must be kept in lockstep by hand,
// there is no shared schema between the two codebases).
//
// Every message in both directions is one frame:
//
//	[ 4B magic "RBY1" ][ 1B opcode ][ 4B payload length, little-endian ][ payload ]
//
// This only works while the device has UsbTransferActivity open (Maintenance -> Down) — the
// device never initiates anything and there is no listener during normal operation.
package usbdevice

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	headerSize      = 4 + 1 + 4 // magic + opcode + length
	maxFilenameLen  = 127
	defaultReadSize = 512
)

var magic = [4]byte{'R', 'B', 'Y', '1'}

type opcode byte

const (
	opPing   opcode = 0x01
	opList   opcode = 0x02
	opGet    opcode = 0x03
	opKey    opcode = 0x04
	opGetAck opcode = 0x05 // sent after fully reading a Get() response body -- see client.go's Get()

	opPong   opcode = 0x81
	opListOk opcode = 0x82
	opGetOk  opcode = 0x83
	opKeyOk  opcode = 0x84
	opErr    opcode = 0x8F
)

// FileInfo is one entry returned by List.
type FileInfo struct {
	Name string `json:"name"`
	Size uint32 `json:"size"`
}

func writeFrame(w io.Writer, op opcode, payload []byte) error {
	header := make([]byte, headerSize)
	copy(header[0:4], magic[:])
	header[4] = byte(op)
	binary.LittleEndian.PutUint32(header[5:9], uint32(len(payload)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// readFrameHeader reads and validates one frame header, returning its opcode and payload length.
func readFrameHeader(r io.Reader) (opcode, uint32, error) {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, 0, fmt.Errorf("usbdevice: reading frame header: %w", err)
	}
	if string(header[0:4]) != string(magic[:]) {
		return 0, 0, fmt.Errorf("usbdevice: bad magic %x (device not in USB Transfer mode?)", header[0:4])
	}
	return opcode(header[4]), binary.LittleEndian.Uint32(header[5:9]), nil
}

func readErrPayload(r io.Reader, length uint32) error {
	msg := make([]byte, length)
	if _, err := io.ReadFull(r, msg); err != nil {
		return fmt.Errorf("usbdevice: device returned an error, and reading its message failed: %w", err)
	}
	return fmt.Errorf("usbdevice: device error: %s", msg)
}
