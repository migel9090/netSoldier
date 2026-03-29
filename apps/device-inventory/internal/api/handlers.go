package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/store"
)

type Handler struct {
	store *store.Store
}

func NewHandler(s *store.Store) *Handler {
	return &Handler{store: s}
}

func (h *Handler) ListDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := h.store.List()
	if err != nil {
		slog.Error("list devices failed", "error", err)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(devices)
}

func (h *Handler) GetDevice(w http.ResponseWriter, r *http.Request) {
	mac := r.PathValue("mac")
	if mac == "" {
		http.Error(w, `{"error":"mac required"}`, http.StatusBadRequest)
		return
	}

	device, err := h.store.GetDevice(mac)
	if err != nil {
		slog.Error("get device failed", "mac", mac, "error", err)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	if device == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(device)
}

func (h *Handler) SetLabels(w http.ResponseWriter, r *http.Request) {
	mac := r.PathValue("mac")
	if mac == "" {
		http.Error(w, `{"error":"mac required"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		Labels []string `json:"labels"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
		return
	}
	if req.Labels == nil {
		req.Labels = []string{}
	}

	if err := h.store.SetLabels(mac, req.Labels); err != nil {
		slog.Error("set labels failed", "mac", mac, "error", err)
		http.Error(w, `{"error":"not found or internal"}`, http.StatusNotFound)
		return
	}

	device, err := h.store.GetDevice(mac)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(device)
}
