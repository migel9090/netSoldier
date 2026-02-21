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
