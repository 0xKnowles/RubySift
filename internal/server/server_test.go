package server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	rscipher "github.com/0xKnowles/RubySift/internal/cipher"
	"github.com/0xKnowles/RubySift/internal/parser"
)

// writeLogFile encrypts each given 39-byte plaintext record into an on-disk
// envelope (1B version + 12B nonce + 2B LE length + ciphertext + 16B tag),
// exactly as Ruby's firmware writeEnvelope() does, and writes the
// concatenated envelopes to a temp .pclog file.
func writeLogFile(t *testing.T, key [rscipher.KeySize]byte, records [][]byte) string {
	t.Helper()
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, rscipher.NonceSize)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	for i, plain := range records {
		nonce := make([]byte, rscipher.NonceSize)
		binary.LittleEndian.PutUint32(nonce, uint32(i)+1)
		sealed := gcm.Seal(nil, nonce, plain, nil)

		buf.WriteByte(rscipher.FormatVersion)
		buf.Write(nonce)
		lenField := make([]byte, rscipher.LengthFieldSize)
		binary.LittleEndian.PutUint16(lenField, uint16(len(plain)))
		buf.Write(lenField)
		buf.Write(sealed)
	}

	path := filepath.Join(t.TempDir(), "20260717.pclog")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func wifiRecord(hour int, mac [6]byte, rssi int8, label string) []byte {
	b := make([]byte, parser.Size)
	binary.LittleEndian.PutUint32(b[0x00:0x04], uint32(hour*3600))
	b[0x04] = byte(parser.RecordWiFiHandshake)
	copy(b[0x05:0x0B], mac[:])
	b[0x0B] = byte(rssi)
	n := copy(b[0x0D:0x0D+24], label)
	b[0x25] = byte(n)
	return b
}

func TestEndToEndDecryptAndAnalyze(t *testing.T) {
	key := rscipher.DeriveKey([]byte("hunter2-master-key"))
	path := writeLogFile(t, key, [][]byte{
		wifiRecord(3, [6]byte{0xAA}, -50, "HomeWiFi"),
		wifiRecord(3, [6]byte{0xAA}, -55, "HomeWiFi"),
	})

	srv := New(http.Dir(t.TempDir())) // no UI assets needed for this test
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	openBody, _ := json.Marshal(map[string]string{
		"path": path,
		"key":  hexKey(key),
	})
	res, err := http.Post(ts.URL+"/api/session/open", "application/json", bytes.NewReader(openBody))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("open status = %d", res.StatusCode)
	}

	var proximity []map[string]any
	mustGetJSON(t, ts.URL+"/api/proximity", &proximity)
	if len(proximity) != 1 {
		t.Fatalf("expected 1 proximity cluster, got %d", len(proximity))
	}
	if proximity[0]["sightings"].(float64) != 2 {
		t.Errorf("sightings = %v", proximity[0]["sightings"])
	}
	if proximity[0]["label"] != "HomeWiFi" {
		t.Errorf("label = %v", proximity[0]["label"])
	}
}

func TestEndToEndWrongKeyRejected(t *testing.T) {
	key := rscipher.DeriveKey([]byte("real-key"))
	wrongKey := rscipher.DeriveKey([]byte("wrong-key"))
	path := writeLogFile(t, key, [][]byte{wifiRecord(1, [6]byte{0x01}, -30, "")})

	srv := New(http.Dir(t.TempDir()))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	openBody, _ := json.Marshal(map[string]string{"path": path, "key": hexKey(wrongKey)})
	res, err := http.Post(ts.URL+"/api/session/open", "application/json", bytes.NewReader(openBody))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for wrong key, got %d", res.StatusCode)
	}
}

func TestEndToEndRequiresSessionBeforeAnalytics(t *testing.T) {
	srv := New(http.Dir(t.TempDir()))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	res, err := http.Get(ts.URL + "/api/pulse")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 with no session loaded, got %d", res.StatusCode)
	}
}

func hexKey(k [rscipher.KeySize]byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, len(k)*2)
	for _, b := range k {
		out = append(out, hexDigits[b>>4], hexDigits[b&0xF])
	}
	return string(out)
}

func mustGetJSON(t *testing.T, url string, v any) {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d", url, res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}
