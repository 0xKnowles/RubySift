package usbdevice

import (
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
		if string(payload) != "20260717.pclog" {
			t.Errorf("device saw filename %q", payload)
		}
		device.sendFrame(opGetOk, want)
	}()

	got, err := client.Get("20260717.pclog")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	<-done
	if string(got) != string(want) {
		t.Fatalf("got %q, want %q", got, want)
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

	_, err := client.Get("nope.pclog")
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
	if _, err := client.Get(string(longName)); err == nil {
		t.Fatal("expected an error for an overlong filename")
	}
}
