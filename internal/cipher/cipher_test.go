package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"
)

// newGCMForTest builds a reference AES-256-GCM AEAD directly from the
// standard library, independent of Session, so tests can construct frames
// without relying on the code under test.
func newGCMForTest(key [KeySize]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithNonceSize(block, NonceSize)
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := DeriveKey([]byte("correct horse battery staple"))
	sess, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}

	plain := make([]byte, RecordSize)
	copy(plain, []byte("0123456789abcdef"))

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	block, _ := newGCMForTest(key)
	sealed := block.Seal(nil, nonce, plain, nil)
	frame := append(append([]byte{}, nonce...), sealed...)

	got, err := sess.DecryptFrame(frame)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch: got %x want %x", got, plain)
	}
}

func TestDecryptFrameWrongKeyFails(t *testing.T) {
	key1 := DeriveKey([]byte("key-one"))
	key2 := DeriveKey([]byte("key-two"))

	block, _ := newGCMForTest(key1)
	nonce := make([]byte, NonceSize)
	plain := make([]byte, RecordSize)
	sealed := block.Seal(nil, nonce, plain, nil)
	frame := append(append([]byte{}, nonce...), sealed...)

	sess, err := NewSession(key2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.DecryptFrame(frame); err == nil {
		t.Fatal("expected authentication failure with wrong key")
	}
}

func TestDecryptFrameRejectsShortFrame(t *testing.T) {
	key := DeriveKey([]byte("x"))
	sess, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.DecryptFrame(make([]byte, FrameSize-1)); err != ErrShortFrame {
		t.Fatalf("expected ErrShortFrame, got %v", err)
	}
}

func TestDecryptStreamMultipleFrames(t *testing.T) {
	key := DeriveKey([]byte("stream-key"))
	sess, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := newGCMForTest(key)

	var buf bytes.Buffer
	want := [][]byte{
		bytes.Repeat([]byte{0x01}, RecordSize),
		bytes.Repeat([]byte{0x02}, RecordSize),
		bytes.Repeat([]byte{0x03}, RecordSize),
	}
	for i, plain := range want {
		nonce := make([]byte, NonceSize)
		nonce[0] = byte(i)
		sealed := block.Seal(nil, nonce, plain, nil)
		buf.Write(nonce)
		buf.Write(sealed)
	}

	var got [][]byte
	err = sess.DecryptStream(&buf, func(record []byte) error {
		cp := append([]byte{}, record...)
		got = append(got, cp)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("record %d mismatch", i)
		}
	}
}

func TestDecryptStreamRejectsTruncatedTrailingFrame(t *testing.T) {
	key := DeriveKey([]byte("k"))
	sess, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := newGCMForTest(key)
	nonce := make([]byte, NonceSize)
	sealed := block.Seal(nil, nonce, make([]byte, RecordSize), nil)

	var buf bytes.Buffer
	buf.Write(nonce)
	buf.Write(sealed)                // one complete, valid frame
	buf.Write([]byte{0, 1, 2, 3, 4}) // trailing partial frame

	err = sess.DecryptStream(&buf, func([]byte) error { return nil })
	if err != ErrShortFrame {
		t.Fatalf("expected ErrShortFrame, got %v", err)
	}
}
