// Package cipher implements the AES-256-GCM decryption pipeline used to
// recover plaintext telemetry records from Ruby's raw .rub log files.
//
// On-disk frame layout (as written by the ESP32-C3 firmware):
//
//	[ 12-byte IV/nonce ][ 16-byte encrypted record ][ 16-byte GCM auth tag ]
//
// Each frame decrypts to exactly one fixed-width 16-byte plaintext record
// (see internal/parser for the record schema), so every frame on disk is
// exactly 44 bytes wide.
package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"io"
)

const (
	NonceSize  = 12
	RecordSize = 16
	TagSize    = 16
	FrameSize  = NonceSize + RecordSize + TagSize
	KeySize    = 32 // AES-256
)

var (
	ErrShortFrame = errors.New("cipher: truncated frame")
	ErrBadKeyLen  = errors.New("cipher: key must decode to 32 bytes")
)

// DeriveKey turns an arbitrary passphrase into a 32-byte AES-256 key via
// SHA-256. The key is only ever held in memory for the lifetime of the
// decryption session and is never written to disk.
func DeriveKey(passphrase []byte) [KeySize]byte {
	return sha256.Sum256(passphrase)
}

// Session wraps a ready-to-use AES-256-GCM cipher bound to one in-memory key.
type Session struct {
	gcm cipher.AEAD
}

// NewSession constructs a decryption session from a raw 32-byte key.
func NewSession(key [KeySize]byte) (*Session, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, NonceSize)
	if err != nil {
		return nil, err
	}
	return &Session{gcm: gcm}, nil
}

// DecryptFrame authenticates and decrypts one 44-byte on-disk frame,
// returning the 16-byte plaintext record.
func (s *Session) DecryptFrame(frame []byte) ([]byte, error) {
	if len(frame) != FrameSize {
		return nil, ErrShortFrame
	}
	nonce := frame[:NonceSize]
	ciphertext := frame[NonceSize:] // 16-byte record + 16-byte tag
	return s.gcm.Open(nil, nonce, ciphertext, nil)
}

// DecryptStream reads fixed-width frames from r and invokes fn with each
// decrypted 16-byte plaintext record in order. It stops at EOF and returns
// nil, or returns the first error encountered (including authentication
// failures, which indicate a wrong key or corrupted log).
func (s *Session) DecryptStream(r io.Reader, fn func(record []byte) error) error {
	buf := make([]byte, FrameSize)
	for {
		_, err := io.ReadFull(r, buf)
		if err == io.EOF {
			return nil
		}
		if err == io.ErrUnexpectedEOF {
			return ErrShortFrame
		}
		if err != nil {
			return err
		}
		record, err := s.DecryptFrame(buf)
		if err != nil {
			return err
		}
		if err := fn(record); err != nil {
			return err
		}
	}
}
