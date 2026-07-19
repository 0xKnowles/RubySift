// Package cipher implements the AES-256-GCM decryption pipeline used to
// recover plaintext telemetry records from Ruby's raw .pclog files.
//
// On-disk envelope layout, matching lib/RubyLog/EncryptedLog.cpp
// (writeEnvelope) in the Ruby firmware:
//
//	[ 1-byte format version ][ 12-byte nonce ][ 2-byte ciphertext length (LE) ]
//	[ ciphertext (== PlaintextSize bytes) ][ 16-byte GCM auth tag ]
//
// No additional authenticated data (AAD) is used — only the plaintext
// payload is encrypted and authenticated; the version/nonce/length header
// is written and read as-is. Every envelope is a fixed EnvelopeSize bytes,
// so record N always starts at byte N*EnvelopeSize.
package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

const (
	FormatVersion   = 1
	NonceSize       = 12
	LengthFieldSize = 2
	TagSize         = 16
	PlaintextSize   = 39                                                        // sizeof(LogRecordPlaintext)
	EnvelopeSize    = 1 + NonceSize + LengthFieldSize + PlaintextSize + TagSize // 70
	KeySize         = 32                                                        // AES-256
)

var (
	ErrShortFrame         = errors.New("cipher: truncated envelope")
	ErrBadKeyLen          = errors.New("cipher: key must decode to 32 bytes")
	ErrUnsupportedVersion = errors.New("cipher: unsupported log format version")
	ErrBadLength          = errors.New("cipher: envelope ciphertext length does not match plaintext size")
)

// DeriveKey turns an arbitrary passphrase into a 32-byte AES-256 key via
// SHA-256. Prefer the device's own 64-hex-char key (Settings -> Reveal log
// key) over a passphrase where possible — Ruby derives its key from
// hardware TRNG + eFuse MAC, not from a human-chosen passphrase.
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

// DecryptEnvelope authenticates and decrypts one EnvelopeSize-byte on-disk
// envelope, returning the PlaintextSize-byte plaintext record.
func (s *Session) DecryptEnvelope(envelope []byte) ([]byte, error) {
	if len(envelope) != EnvelopeSize {
		return nil, ErrShortFrame
	}
	version := envelope[0]
	if version != FormatVersion {
		return nil, ErrUnsupportedVersion
	}
	nonce := envelope[1 : 1+NonceSize]
	ctLen := binary.LittleEndian.Uint16(envelope[1+NonceSize : 1+NonceSize+LengthFieldSize])
	if ctLen != PlaintextSize {
		return nil, ErrBadLength
	}
	rest := envelope[1+NonceSize+LengthFieldSize:] // ciphertext + tag
	return s.gcm.Open(nil, nonce, rest, nil)
}

// DecryptStream reads fixed-width envelopes from r and invokes fn with each
// decrypted plaintext record in order. It stops at EOF and returns nil, or
// returns the first error encountered (including authentication failures,
// which indicate a wrong key or corrupted log).
func (s *Session) DecryptStream(r io.Reader, fn func(record []byte) error) error {
	buf := make([]byte, EnvelopeSize)
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
		record, err := s.DecryptEnvelope(buf)
		if err != nil {
			return err
		}
		if err := fn(record); err != nil {
			return err
		}
	}
}
