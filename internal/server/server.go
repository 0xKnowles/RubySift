// Package server exposes RubySift's loopback-only HTTP API and serves the
// embedded dashboard frontend. All decrypted telemetry and the decryption
// key itself live only in the Server's in-memory session state; nothing is
// ever persisted to disk, and Close wipes the key material.
package server

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/0xKnowles/RubySift/internal/analytics"
	"github.com/0xKnowles/RubySift/internal/cipher"
	"github.com/0xKnowles/RubySift/internal/parser"
)

// Session holds the decrypted results of one .pclog file for as long as
// the app is open. The key is zeroed and dropped as soon as decoding
// finishes.
type Session struct {
	mu         sync.RWMutex
	loaded     bool
	sourceFile string
	records    []parser.Record
}

func (s *Session) reset() {
	s.loaded = false
	s.sourceFile = ""
	s.records = nil
}

// Server wires the Session to HTTP handlers plus the embedded static UI.
type Server struct {
	mux     *http.ServeMux
	session *Session
}

func New(assets http.FileSystem) *Server {
	s := &Server{mux: http.NewServeMux(), session: &Session{}}
	s.routes(assets)
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes(assets http.FileSystem) {
	s.mux.Handle("/", http.FileServer(assets))
	s.mux.HandleFunc("/api/session/open", s.handleOpen)
	s.mux.HandleFunc("/api/session/close", s.handleClose)
	s.mux.HandleFunc("/api/session/status", s.handleStatus)
	s.mux.HandleFunc("/api/records", s.handleRecords)
	s.mux.HandleFunc("/api/pulse", s.handlePulse)
	s.mux.HandleFunc("/api/proximity", s.handleProximity)
	s.mux.HandleFunc("/api/usb/ports", s.handleUsbPorts)
	s.mux.HandleFunc("/api/usb/list", s.handleUsbList)
	s.mux.HandleFunc("/api/usb/pull", s.handleUsbPull)
}

type openRequest struct {
	Path       string `json:"path"`
	Key        string `json:"key"`        // 64 hex chars = raw 32-byte AES-256 key
	Passphrase string `json:"passphrase"` // alternative to Key: derived via SHA-256
}

type openResponse struct {
	Records int    `json:"records"`
	Source  string `json:"source"`
}

func resolveKey(req openRequest) ([cipher.KeySize]byte, error) {
	switch {
	case req.Key != "":
		raw, err := hex.DecodeString(req.Key)
		if err != nil {
			return [cipher.KeySize]byte{}, fmt.Errorf("key must be hex-encoded: %w", err)
		}
		if len(raw) != cipher.KeySize {
			return [cipher.KeySize]byte{}, cipher.ErrBadKeyLen
		}
		var k [cipher.KeySize]byte
		copy(k[:], raw)
		return k, nil
	case req.Passphrase != "":
		return cipher.DeriveKey([]byte(req.Passphrase)), nil
	default:
		return [cipher.KeySize]byte{}, errors.New("either key or passphrase is required")
	}
}

func (s *Server) handleOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req openRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Path == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}

	key, err := resolveKey(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer zero(key[:]) // key never persists past this request

	f, err := os.Open(req.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, "cannot open log file: "+err.Error())
		return
	}
	defer f.Close()

	records, err := decryptRecords(f, key)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "decryption failed (wrong key or corrupted log): "+err.Error())
		return
	}

	s.loadSession(req.Path, records)
	writeJSON(w, http.StatusOK, openResponse{
		Records: len(records),
		Source:  req.Path,
	})
}

// decryptRecords runs the full AES-256-GCM decrypt + record-parse pipeline over r. Shared by the
// local-file-path flow (handleOpen) and the USB pull flow (handleUsbPull) — neither writes the
// source bytes to disk, they just differ in where the encrypted bytes come from.
func decryptRecords(r io.Reader, key [cipher.KeySize]byte) ([]parser.Record, error) {
	sess, err := cipher.NewSession(key)
	if err != nil {
		return nil, err
	}
	var records []parser.Record
	err = sess.DecryptStream(r, func(plain []byte) error {
		rec, err := parser.Decode(plain)
		if err != nil {
			return err
		}
		records = append(records, rec)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return records, nil
}

func (s *Server) loadSession(source string, records []parser.Record) {
	s.session.mu.Lock()
	s.session.loaded = true
	s.session.sourceFile = source
	s.session.records = records
	s.session.mu.Unlock()
}

func (s *Server) handleClose(w http.ResponseWriter, r *http.Request) {
	s.session.mu.Lock()
	s.session.reset()
	s.session.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"closed": true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.session.mu.RLock()
	defer s.session.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"loaded":  s.session.loaded,
		"source":  s.session.sourceFile,
		"records": len(s.session.records),
	})
}

func (s *Server) requireLoaded(w http.ResponseWriter) bool {
	s.session.mu.RLock()
	loaded := s.session.loaded
	s.session.mu.RUnlock()
	if !loaded {
		writeError(w, http.StatusConflict, "no session loaded; POST /api/session/open first")
	}
	return loaded
}

func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request) {
	if !s.requireLoaded(w) {
		return
	}
	s.session.mu.RLock()
	defer s.session.mu.RUnlock()
	writeJSON(w, http.StatusOK, s.session.records)
}

func (s *Server) handlePulse(w http.ResponseWriter, r *http.Request) {
	if !s.requireLoaded(w) {
		return
	}
	s.session.mu.RLock()
	defer s.session.mu.RUnlock()
	writeJSON(w, http.StatusOK, analytics.PulseGrid(s.session.records))
}

func (s *Server) handleProximity(w http.ResponseWriter, r *http.Request) {
	if !s.requireLoaded(w) {
		return
	}
	s.session.mu.RLock()
	defer s.session.mu.RUnlock()
	writeJSON(w, http.StatusOK, analytics.ProximityClusters(s.session.records))
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
