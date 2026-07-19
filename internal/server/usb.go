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
// out of UsbTransferActivity between calls. Keeping one connection open for the whole USB session
// avoids the extra close/reopen cycles that trigger it.
//
// mu guards the entire duration of each Do() call, not just opening/replacing the client — the
// protocol is a strict request/response exchange over one shared wire, so two HTTP requests
// racing to use it concurrently (e.g. a double-click) can interleave their writes and reads and
// each read back the other's response. That was observed directly: a List call's response reader
// once received a genuine, well-formed kOpKeyOk frame — the previous request's answer, not
// corruption — because both requests' Client method calls were running unsynchronized on the same
// port at once.
type usbConn struct {
	mu     sync.Mutex
	port   string
	client *usbdevice.Client
}

// Do runs fn against the live client for port under an exclusive lock held for fn's entire
// duration, opening a new connection first if none exists yet or the caller asked for a different
// port than the one currently held. If fn returns an error, the connection is closed and forgotten
// — a connection that errored mid-exchange isn't safe to reuse — so the next Do() call reopens
// cleanly rather than reading whatever is left over on the wire.
func (u *usbConn) Do(port string, fn func(*usbdevice.Client) error) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.client == nil || u.port != port {
		if u.client != nil {
			u.client.Close()
			u.client = nil
			u.port = ""
		}
		client, err := usbdevice.Open(port)
		if err != nil {
			return err
		}
		u.client = client
		u.port = port
	}

	if err := fn(u.client); err != nil {
		u.client.Close()
		u.client = nil
		u.port = ""
		return err
	}
	return nil
}

// drop closes and forgets the current connection, if any.
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

	var files []usbdevice.FileInfo
	err := s.usb.Do(req.Port, func(client *usbdevice.Client) error {
		var err error
		files, err = client.List()
		return err
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, files)
}

type usbPullRequest struct {
	Port string `json:"port"`
	Name string `json:"name"`
	// Size is the file's size as already reported by a prior List() call (the frontend has it
	// from rendering the file picker) — used only for Get()'s progress reporting, not correctness;
	// the device's own chunk responses are what actually determine when the transfer is done.
	Size uint32 `json:"size"`
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

	var key [cipher.KeySize]byte
	if req.Key != "" {
		raw, err := hex.DecodeString(req.Key)
		if err != nil || len(raw) != cipher.KeySize {
			writeError(w, http.StatusBadRequest, "key must be a 64-character hex string")
			return
		}
		copy(key[:], raw)
	}
	defer zero(key[:])

	// Key() and Get() run as one atomic exchange under usb.Do's lock — if a request supplying its
	// own key only needed Get(), a concurrent request could otherwise interleave a Key() call
	// between our two device round trips.
	var data []byte
	err := s.usb.Do(req.Port, func(client *usbdevice.Client) error {
		if req.Key == "" {
			var err error
			key, err = client.Key()
			if err != nil {
				return fmt.Errorf("fetching device key: %w", err)
			}
		}
		var err error
		data, err = client.Get(req.Name, req.Size)
		return err
	})
	if err != nil {
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
