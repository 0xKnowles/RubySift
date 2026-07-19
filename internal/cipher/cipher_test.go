package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// newGCMForTest builds a reference AES-256-GCM AEAD directly from the
// standard library, independent of Session, so tests can construct
// envelopes without relying on the code under test.
func newGCMForTest(key [KeySize]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithNonceSize(block, NonceSize)
}

// sealEnvelope builds one on-disk envelope exactly as Ruby's firmware
// writeEnvelope() does: 1B version + 12B nonce + 2B LE ciphertext length +
// ciphertext + 16B tag.
func sealEnvelope(t *testing.T, gcm cipher.AEAD, nonce, plain []byte) []byte {
	t.Helper()
	sealed := gcm.Seal(nil, nonce, plain, nil) // ciphertext || tag
	env := make([]byte, 0, EnvelopeSize)
	env = append(env, FormatVersion)
	env = append(env, nonce...)
	lenField := make([]byte, LengthFieldSize)
	binary.LittleEndian.PutUint16(lenField, uint16(len(plain)))
	env = append(env, lenField...)
	env = append(env, sealed...)
	return env
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := DeriveKey([]byte("correct horse battery staple"))
	sess, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := newGCMForTest(key)
	if err != nil {
		t.Fatal(err)
	}

	plain := make([]byte, PlaintextSize)
	copy(plain, []byte("0123456789abcdef0123456789abcdef01234"))

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	env := sealEnvelope(t, gcm, nonce, plain)
	if len(env) != EnvelopeSize {
		t.Fatalf("envelope size = %d, want %d", len(env), EnvelopeSize)
	}

	got, err := sess.DecryptEnvelope(env)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch: got %x want %x", got, plain)
	}
}

func TestDecryptEnvelopeWrongKeyFails(t *testing.T) {
	key1 := DeriveKey([]byte("key-one"))
	key2 := DeriveKey([]byte("key-two"))

	gcm, _ := newGCMForTest(key1)
	nonce := make([]byte, NonceSize)
	env := sealEnvelope(t, gcm, nonce, make([]byte, PlaintextSize))

	sess, err := NewSession(key2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.DecryptEnvelope(env); err == nil {
		t.Fatal("expected authentication failure with wrong key")
	}
}

func TestDecryptEnvelopeRejectsShortFrame(t *testing.T) {
	sess, err := NewSession(DeriveKey([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.DecryptEnvelope(make([]byte, EnvelopeSize-1)); err != ErrShortFrame {
		t.Fatalf("expected ErrShortFrame, got %v", err)
	}
}

func TestDecryptEnvelopeRejectsUnsupportedVersion(t *testing.T) {
	key := DeriveKey([]byte("y"))
	sess, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, _ := newGCMForTest(key)
	nonce := make([]byte, NonceSize)
	env := sealEnvelope(t, gcm, nonce, make([]byte, PlaintextSize))
	env[0] = FormatVersion + 1

	if _, err := sess.DecryptEnvelope(env); err != ErrUnsupportedVersion {
		t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
	}
}

func TestDecryptEnvelopeRejectsBadLength(t *testing.T) {
	key := DeriveKey([]byte("z"))
	sess, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, _ := newGCMForTest(key)
	nonce := make([]byte, NonceSize)
	env := sealEnvelope(t, gcm, nonce, make([]byte, PlaintextSize))
	binary.LittleEndian.PutUint16(env[1+NonceSize:1+NonceSize+LengthFieldSize], 5)

	if _, err := sess.DecryptEnvelope(env); err != ErrBadLength {
		t.Fatalf("expected ErrBadLength, got %v", err)
	}
}

func TestDecryptStreamMultipleEnvelopes(t *testing.T) {
	key := DeriveKey([]byte("stream-key"))
	sess, err := NewSession(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, _ := newGCMForTest(key)

	var buf bytes.Buffer
	want := [][]byte{
		bytes.Repeat([]byte{0x01}, PlaintextSize),
		bytes.Repeat([]byte{0x02}, PlaintextSize),
		bytes.Repeat([]byte{0x03}, PlaintextSize),
	}
	for i, plain := range want {
		nonce := make([]byte, NonceSize)
		nonce[0] = byte(i)
		buf.Write(sealEnvelope(t, gcm, nonce, plain))
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
	gcm, _ := newGCMForTest(key)
	nonce := make([]byte, NonceSize)
	env := sealEnvelope(t, gcm, nonce, make([]byte, PlaintextSize))

	var buf bytes.Buffer
	buf.Write(env)                   // one complete, valid envelope
	buf.Write([]byte{0, 1, 2, 3, 4}) // trailing partial envelope

	err = sess.DecryptStream(&buf, func([]byte) error { return nil })
	if err != ErrShortFrame {
		t.Fatalf("expected ErrShortFrame, got %v", err)
	}
}
