package usbdevice

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"testing"
)

// fakeDevice plays the firmware's side of the protocol against a Client under test, so these
// tests exercise the real framing/parsing logic without any hardware. net.Pipe gives us a
// synchronous, full-duplex io.ReadWriteCloser pair — one end wrapped as the Client's "serial
// port", the other driven directly by the test as the simulated device.
type fakeDevice struct {
	t    *testing.T
	conn net.Conn
}

func newFakeDevice(t *testing.T) (*Client, *fakeDevice) {
	t.Helper()
	clientSide, deviceSide := net.Pipe()
	t.Cleanup(func() { clientSide.Close(); deviceSide.Close() })
	return &Client{port: clientSide}, &fakeDevice{t: t, conn: deviceSide}
}

func (d *fakeDevice) recvFrame() (opcode, []byte) {
	d.t.Helper()
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(d.conn, header); err != nil {
		d.t.Fatalf("device: reading request header: %v", err)
	}
	if string(header[0:4]) != string(magic[:]) {
		d.t.Fatalf("device: bad magic in request: %x", header[0:4])
	}
	length := binary.LittleEndian.Uint32(header[5:9])
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(d.conn, payload); err != nil {
			d.t.Fatalf("device: reading request payload: %v", err)
		}
	}
	return opcode(header[4]), payload
}

func (d *fakeDevice) sendFrame(op opcode, payload []byte) {
	d.t.Helper()
	if err := writeFrame(d.conn, op, payload); err != nil {
		d.t.Fatalf("device: sending response: %v", err)
	}
}

func TestClientPing(t *testing.T) {
	client, device := newFakeDevice(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		op, _ := device.recvFrame()
		if op != opPing {
			t.Errorf("device saw opcode 0x%02x, want opPing", op)
		}
		device.sendFrame(opPong, nil)
	}()

	if err := client.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	<-done
}

func TestClientList(t *testing.T) {
	client, device := newFakeDevice(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		op, _ := device.recvFrame()
		if op != opList {
			t.Errorf("device saw opcode 0x%02x, want opList", op)
		}

		var payload []byte
		for _, f := range []FileInfo{{Name: "20260717.pclog", Size: 4970}, {Name: "20260718.pclog", Size: 140}} {
			nameLen := make([]byte, 2)
			binary.LittleEndian.PutUint16(nameLen, uint16(len(f.Name)))
			payload = append(payload, nameLen...)
			payload = append(payload, f.Name...)
			sizeBuf := make([]byte, 4)
			binary.LittleEndian.PutUint32(sizeBuf, f.Size)
			payload = append(payload, sizeBuf...)
		}
		device.sendFrame(opListOk, payload)
	}()

	files, err := client.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	<-done

	want := []FileInfo{{Name: "20260717.pclog", Size: 4970}, {Name: "20260718.pclog", Size: 140}}
	if len(files) != len(want) {
		t.Fatalf("got %d files, want %d", len(files), len(want))
	}
	for i := range want {
		if files[i] != want[i] {
			t.Errorf("file %d = %+v, want %+v", i, files[i], want[i])
		}
	}
}

func TestClientListEmpty(t *testing.T) {
	client, device := newFakeDevice(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		device.recvFrame()
		device.sendFrame(opListOk, nil)
	}()

	files, err := client.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	<-done
	if len(files) != 0 {
		t.Fatalf("got %d files, want 0", len(files))
	}
}

func TestClientGet(t *testing.T) {
	client, device := newFakeDevice(t)
	want := []byte("pretend this is a decrypted-looking .pclog body")
	done := make(chan struct{})
	go func() {
		defer close(done)
		op, payload := device.recvFrame()
		if op != opGet {
			t.Errorf("device saw opcode 0x%02x, want opGet", op)
		}
		// payload = [4B offset LE][4B length LE][filename]
		if len(payload) < 8 {
			t.Errorf("get request payload too short: %d bytes", len(payload))
			return
		}
		offset := binary.LittleEndian.Uint32(payload[0:4])
		length := binary.LittleEndian.Uint32(payload[4:8])
		name := string(payload[8:])
		if offset != 0 {
			t.Errorf("device saw offset %d, want 0", offset)
		}
		if length != chunkSize {
			t.Errorf("device saw requested length %d, want %d", length, chunkSize)
		}
		if name != "20260717.pclog" {
			t.Errorf("device saw filename %q", name)
		}
		device.sendFrame(opGetOk, want)

		// The client sends this once it's fully read the payload -- see Get()'s comment. net.Pipe
		// is unbuffered/synchronous, so without a reader here the client's write would block
		// forever and hang the test.
		ackOp, _ := device.recvFrame()
		if ackOp != opGetAck {
			t.Errorf("device saw opcode 0x%02x after Get, want opGetAck", ackOp)
		}
	}()

	// want is far shorter than chunkSize, so the device's single short reply signals EOF and Get
	// returns after exactly one chunk exchange.
	got, err := client.Get("20260717.pclog", uint32(len(want)))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	<-done
	if string(got) != string(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestClientGetMultipleChunks(t *testing.T) {
	client, device := newFakeDevice(t)
	// Two full-size chunks plus a short final one, so Get() must issue three requests before
	// recognizing EOF from the last (short) response.
	chunk1 := bytes.Repeat([]byte{0xAA}, chunkSize)
	chunk2 := bytes.Repeat([]byte{0xBB}, chunkSize)
	chunk3 := []byte("tail")
	want := append(append(append([]byte{}, chunk1...), chunk2...), chunk3...)

	done := make(chan struct{})
	go func() {
		defer close(done)
		wantOffset := uint32(0)
		for _, chunk := range [][]byte{chunk1, chunk2, chunk3} {
			op, payload := device.recvFrame()
			if op != opGet {
				t.Errorf("device saw opcode 0x%02x, want opGet", op)
			}
			offset := binary.LittleEndian.Uint32(payload[0:4])
			if offset != wantOffset {
				t.Errorf("device saw offset %d, want %d", offset, wantOffset)
			}
			wantOffset += uint32(len(chunk))
			device.sendFrame(opGetOk, chunk)
			ackOp, _ := device.recvFrame()
			if ackOp != opGetAck {
				t.Errorf("device saw opcode 0x%02x after Get, want opGetAck", ackOp)
			}
		}
	}()

	got, err := client.Get("big.pclog", uint32(len(want)))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	<-done
	if !bytes.Equal(got, want) {
		t.Fatalf("got %d bytes, want %d bytes (mismatch)", len(got), len(want))
	}
}

func TestClientGetNotFound(t *testing.T) {
	client, device := newFakeDevice(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		device.recvFrame()
		device.sendFrame(opErr, []byte("file not found"))
	}()

	_, err := client.Get("nope.pclog", 0)
	<-done
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestClientKey(t *testing.T) {
	client, device := newFakeDevice(t)
	wantKey := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	done := make(chan struct{})
	go func() {
		defer close(done)
		op, _ := device.recvFrame()
		if op != opKey {
			t.Errorf("device saw opcode 0x%02x, want opKey", op)
		}
		device.sendFrame(opKeyOk, []byte(wantKey))
	}()

	key, err := client.Key()
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	<-done

	want, _ := hex.DecodeString(wantKey)
	if hex.EncodeToString(key[:]) != hex.EncodeToString(want) {
		t.Fatalf("got key %x, want %x", key, want)
	}
}

func TestClientGetRejectsOverlongFilename(t *testing.T) {
	client, _ := newFakeDevice(t)
	longName := make([]byte, maxFilenameLen+1)
	for i := range longName {
		longName[i] = 'a'
	}
	if _, err := client.Get(string(longName), 0); err == nil {
		t.Fatal("expected an error for an overlong filename")
	}
}
