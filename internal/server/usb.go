package server

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"

	"github.com/0xKnowles/RubySift/internal/cipher"
	"github.com/0xKnowles/RubySift/internal/usbdevice"
)

// usbConn holds at most one live connection to a Ruby device's USB Transfer screen, reused across
// requests instead of opening a fresh serial connection per HTTP call.
//
// This matters beyond efficiency: closing a serial port commonly drops DTR as a "hang up" signal,
// and plenty of ESP32 boards (including native-USB C3 boards, for esptool's auto-reset trick) wire
// DTR to EN/reset. Opening and closing a connection per request was observed resetting the device
// out of UsbTransferActivity between calls (e.g. List succeeding, then Pull's fresh connection
// landing on a device that had already rebooted back to normal, unmuted logging — visible as
// "bad magic" errors containing what's obviously a log line, not a protocol frame). Keeping one
// connection open for the whole USB session avoids the extra close/reopen cycles that trigger it.
type usbConn struct {
	mu     sync.Mutex
	port   string
	client *usbdevice.Client
}

// ensure returns the live client for port, opening a new connection if none exists yet or the
// caller asked for a different port than the one currently held.
func (u *usbConn) ensure(port string) (*usbdevice.Client, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.client != nil && u.port == port {
		return u.client, nil
	}
	if u.client != nil {
		u.client.Close()
		u.client = nil
	}

	client, err := usbdevice.Open(port)
	if err != nil {
		return nil, err
	}
	u.client = client
	u.port = port
	return client, nil
}

// drop closes and forgets the current connection, used when a request on it fails — a broken
// connection isn't worth reusing, and the next request will reopen cleanly.
func (u *usbConn) drop() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.client != nil {
		u.client.Close()
		u.client = nil
		u.port = ""
	}
}

func (s *Server) handleUsbDisconnect(w http.ResponseWriter, r *http.Request) {
	s.usb.drop()
	writeJSON(w, http.StatusOK, map[string]bool{"disconnected": true})
}

func (s *Server) handleUsbPorts(w http.ResponseWriter, r *http.Request) {
	ports, err := usbdevice.ListPorts()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ports)
}

type usbListRequest struct {
	Port string `json:"port"`
}

func (s *Server) handleUsbList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req usbListRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Port == "" {
		writeError(w, http.StatusBadRequest, "port is required")
		return
	}

	client, err := s.usb.ensure(req.Port)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	files, err := client.List()
	if err != nil {
		s.usb.drop()
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, files)
}

type usbPullRequest struct {
	Port string `json:"port"`
	Name string `json:"name"`
	// Key is optional: if empty, the device's own key is fetched over the same USB connection
	// (Client.Key()) rather than requiring it typed in — physical possession is already
	// established by the fact that a live USB Transfer connection exists at all.
	Key string `json:"key"`
}

func (s *Server) handleUsbPull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req usbPullRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Port == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, "port and name are required")
		return
	}

	client, err := s.usb.ensure(req.Port)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	var key [cipher.KeySize]byte
	if req.Key != "" {
		raw, err := hex.DecodeString(req.Key)
		if err != nil || len(raw) != cipher.KeySize {
			writeError(w, http.StatusBadRequest, "key must be a 64-character hex string")
			return
		}
		copy(key[:], raw)
	} else {
		key, err = client.Key()
		if err != nil {
			s.usb.drop()
			writeError(w, http.StatusBadGateway, fmt.Errorf("fetching device key: %w", err).Error())
			return
		}
	}
	defer zero(key[:])

	data, err := client.Get(req.Name)
	if err != nil {
		s.usb.drop()
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	records, err := decryptRecords(bytes.NewReader(data), key)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "decryption failed (wrong key or corrupted log): "+err.Error())
		return
	}

	s.loadSession("usb:"+req.Name, records)
	writeJSON(w, http.StatusOK, openResponse{
		Records: len(records),
		Source:  "usb:" + req.Name,
	})
}
