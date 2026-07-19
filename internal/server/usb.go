package server

import (
	"bytes"
	"encoding/hex"
	"net/http"

	"github.com/0xKnowles/RubySift/internal/cipher"
	"github.com/0xKnowles/RubySift/internal/usbdevice"
)

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

	client, err := usbdevice.Open(req.Port)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer client.Close()

	files, err := client.List()
	if err != nil {
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

	client, err := usbdevice.Open(req.Port)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer client.Close()

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
			writeError(w, http.StatusBadGateway, "fetching device key: "+err.Error())
			return
		}
	}
	defer zero(key[:])

	data, err := client.Get(req.Name)
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
