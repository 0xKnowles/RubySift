package usbdevice

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"go.bug.st/serial"
)

// ListPorts returns the serial ports currently visible to the OS. A Ruby device shows up here as
// an ordinary USB-CDC ACM port while UsbTransferActivity is open on it — there's no vendor/product
// ID filtering, since the ESP32-C3's USB Serial/JTAG controller doesn't expose fixed ones distinct
// from any other CDC-ACM device.
func ListPorts() ([]string, error) {
	ports, err := serial.GetPortsList()
	if err != nil {
		return nil, fmt.Errorf("usbdevice: listing serial ports: %w", err)
	}
	return ports, nil
}

// Client is a connection to one Ruby device's USB Transfer screen. Callers are expected to reuse
// one Client across multiple List/Get/Key calls rather than reopening per call — see
// internal/server/usb.go's usbConn, which holds one open for as long as the dashboard's USB
// session lasts, both for efficiency and because repeated open/close cycles were observed
// resetting the device (see Open's comment).
//
// port is io.ReadWriteCloser rather than the concrete serial.Port so tests can drive the protocol
// logic against an in-memory fake instead of real hardware.
type Client struct {
	port io.ReadWriteCloser
}

// Open connects to the serial port at the given path (e.g. "/dev/ttyACM0", "COM5").
func Open(portName string) (*Client, error) {
	// go.bug.st/serial defaults InitialStatusBits to DTR=true, RTS=true when left nil. Plenty of
	// ESP32 boards — including native-USB C3 boards, for esptool's auto-reset-into-bootloader
	// trick — wire those lines to EN/IO0, so asserting them on open can reset the chip out from
	// under UsbTransferActivity the moment we connect. Deasserted here so opening the port never
	// touches the device's reset/boot-mode pins.
	mode := &serial.Mode{
		BaudRate:          115200,
		InitialStatusBits: &serial.ModemOutputBits{DTR: false, RTS: false},
	}
	port, err := serial.Open(portName, mode)
	if err != nil {
		return nil, fmt.Errorf("usbdevice: opening %s: %w", portName, err)
	}
	// Applies per underlying Read() call, not to the overall exchange — io.ReadFull loops calling
	// Read until it has everything, so this only trips if a single Read goes this long without any
	// new byte arriving. Get() can stream a multi-megabyte .pclog in 512-byte chunks straight off
	// the SD card, and an occasional slow card read shouldn't spuriously fail the whole transfer.
	if err := port.SetReadTimeout(30 * time.Second); err != nil {
		port.Close()
		return nil, fmt.Errorf("usbdevice: setting read timeout: %w", err)
	}
	return &Client{port: port}, nil
}

func (c *Client) Close() error { return c.port.Close() }

// inputFlusher is satisfied by the real serial.Port (not by the io.ReadWriteCloser test fakes,
// which have nothing to flush).
type inputFlusher interface {
	ResetInputBuffer() error
}

// discardStaleInput drops any bytes already sitting in the OS's serial receive buffer before we
// write a new request. Confirmed necessary on real hardware: the device's own request counter
// kept incrementing normally (never crashed, never left UsbTransferActivity) while the host still
// read back "bad magic" -- meaning an earlier request's response, or some other leftover bytes,
// were sitting unread ahead of the next request's actual response. Every protocol method starts
// clean now instead of trusting that the last exchange left nothing behind.
func (c *Client) discardStaleInput() {
	if f, ok := c.port.(inputFlusher); ok {
		_ = f.ResetInputBuffer()
	}
}

// Ping verifies the device is connected and has UsbTransferActivity open.
func (c *Client) Ping() error {
	c.discardStaleInput()
	if err := writeFrame(c.port, opPing, nil); err != nil {
		return err
	}
	op, _, err := readFrameHeader(c.port)
	if err != nil {
		return err
	}
	if op != opPong {
		return fmt.Errorf("usbdevice: expected pong, got opcode 0x%02x", op)
	}
	return nil
}

// List returns every file in the device's log directory.
func (c *Client) List() ([]FileInfo, error) {
	c.discardStaleInput()
	if err := writeFrame(c.port, opList, nil); err != nil {
		return nil, err
	}
	op, length, err := readFrameHeader(c.port)
	if err != nil {
		return nil, err
	}
	if op == opErr {
		return nil, readErrPayload(c.port, length)
	}
	if op != opListOk {
		return nil, fmt.Errorf("usbdevice: expected list-ok, got opcode 0x%02x", op)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(c.port, payload); err != nil {
		return nil, fmt.Errorf("usbdevice: reading list payload: %w", err)
	}

	var files []FileInfo
	for offset := 0; offset < len(payload); {
		if offset+2 > len(payload) {
			return nil, fmt.Errorf("usbdevice: truncated list entry (name length)")
		}
		nameLen := int(binary.LittleEndian.Uint16(payload[offset : offset+2]))
		offset += 2
		if offset+nameLen+4 > len(payload) {
			return nil, fmt.Errorf("usbdevice: truncated list entry (name/size)")
		}
		name := string(payload[offset : offset+nameLen])
		offset += nameLen
		size := binary.LittleEndian.Uint32(payload[offset : offset+4])
		offset += 4
		files = append(files, FileInfo{Name: name, Size: size})
	}
	return files, nil
}

// Get fetches one file's raw bytes by name (no directory prefix).
func (c *Client) Get(name string) ([]byte, error) {
	if len(name) == 0 || len(name) > maxFilenameLen {
		return nil, fmt.Errorf("usbdevice: filename length must be 1-%d bytes", maxFilenameLen)
	}
	c.discardStaleInput()
	if err := writeFrame(c.port, opGet, []byte(name)); err != nil {
		return nil, err
	}
	op, length, err := readFrameHeader(c.port)
	if err != nil {
		return nil, err
	}
	if op == opErr {
		return nil, readErrPayload(c.port, length)
	}
	if op != opGetOk {
		return nil, fmt.Errorf("usbdevice: expected get-ok, got opcode 0x%02x", op)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(c.port, data); err != nil {
		return nil, fmt.Errorf("usbdevice: reading file body: %w", err)
	}
	return data, nil
}

// Key fetches the device's 64-hex-char AES-256 decryption key. Reachable only because we already
// hold a live connection to UsbTransferActivity — the same physical-possession bar as reading the
// key off the device's own Settings screen.
func (c *Client) Key() ([32]byte, error) {
	var key [32]byte
	c.discardStaleInput()
	if err := writeFrame(c.port, opKey, nil); err != nil {
		return key, err
	}
	op, length, err := readFrameHeader(c.port)
	if err != nil {
		return key, err
	}
	if op == opErr {
		return key, readErrPayload(c.port, length)
	}
	if op != opKeyOk {
		return key, fmt.Errorf("usbdevice: expected key-ok, got opcode 0x%02x", op)
	}

	hexKey := make([]byte, length)
	if _, err := io.ReadFull(c.port, hexKey); err != nil {
		return key, fmt.Errorf("usbdevice: reading key payload: %w", err)
	}
	raw, err := hex.DecodeString(string(hexKey))
	if err != nil || len(raw) != len(key) {
		return key, fmt.Errorf("usbdevice: device returned a malformed key")
	}
	copy(key[:], raw)
	return key, nil
}
