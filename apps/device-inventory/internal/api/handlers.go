package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"

	ch "github.com/migel9090/netSoldier/apps/device-inventory/internal/clickhouse"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/store"
)

// Paging and body limits (contract v2, section 5).
const (
	DefaultPageSize = 500
	MaxPageSize     = 1000
	maxLabelsBody   = 16 << 10
)

// Handler serves the inventory endpoints.
type Handler struct {
	store *store.Store
	ch    *ch.Client

	// OnLabels, when set, is called with a device whose labels changed.
	OnLabels func(*store.Device)
}

// NewHandler returns a handler over s; chClient may be nil.
func NewHandler(s *store.Store, chClient *ch.Client) *Handler {
	return &Handler{store: s, ch: chClient}
}

// Register adds the inventory routes to mux. Patterns are chosen so that
// /devices/by-ip/{ip} never collides with the per-device views.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /devices", h.ListDevices)
	mux.HandleFunc("GET /devices/by-ip/{ip}", h.GetDeviceByIP)
	mux.HandleFunc("GET /devices/{mac}", h.GetDevice)
	mux.HandleFunc("GET /devices/{mac}/{view}", h.DeviceView)
	mux.HandleFunc("PUT /devices/{mac}/labels", h.SetLabels)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// pathMAC returns the canonical form of the {mac} path value.
func pathMAC(w http.ResponseWriter, r *http.Request) (string, bool) {
	mac, ok := discovery.ParseMAC(r.PathValue("mac"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid mac")
	}
	return mac, ok
}

func queryInt(r *http.Request, name string, def int) (int, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// ListDevices serves GET /devices?limit=&offset=: a JSON array in trust
// order, total in X-Total-Count. limit defaults to 500 and is capped at 1000.
func (h *Handler) ListDevices(w http.ResponseWriter, r *http.Request) {
	limit, ok := queryInt(r, "limit", DefaultPageSize)
	if !ok || limit == 0 {
		writeError(w, http.StatusBadRequest, "limit must be a positive integer")
		return
	}
	offset, ok := queryInt(r, "offset", 0)
	if !ok {
		writeError(w, http.StatusBadRequest, "offset must be a non-negative integer")
		return
	}
	limit = min(limit, MaxPageSize)

	devices, err := h.store.List(limit, offset)
	if err != nil {
		slog.Error("list devices failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	w.Header().Set("X-Total-Count", strconv.Itoa(h.store.Count()))
	writeJSON(w, http.StatusOK, devices)
}

// GetDevice serves GET /devices/{mac}.
func (h *Handler) GetDevice(w http.ResponseWriter, r *http.Request) {
	mac, ok := pathMAC(w, r)
	if !ok {
		return
	}
	device, err := h.store.GetDevice(mac)
	if err != nil {
		slog.Error("get device failed", "mac", mac, "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if device == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, device)
}

// GetDeviceByIP serves GET /devices/by-ip/{ip}: the device currently holding
// the address, or 404. "Currently" means a binding confirmed within
// BINDING_TTL; the response's ip_state (tentative or live) and conflicts say
// how much to trust it.
func (h *Handler) GetDeviceByIP(w http.ResponseWriter, r *http.Request) {
	addr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil || addr.Zone() != "" {
		writeError(w, http.StatusBadRequest, "invalid ip")
		return
	}
	device, err := h.store.GetByIP(addr.Unmap().String())
	if err != nil {
		slog.Error("get device by ip failed", "ip", addr.String(), "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if device == nil {
		writeError(w, http.StatusNotFound, "no current holder")
		return
	}
	writeJSON(w, http.StatusOK, device)
}

// DeviceView serves GET /devices/{mac}/{connections|dns|alerts}.
func (h *Handler) DeviceView(w http.ResponseWriter, r *http.Request) {
	switch r.PathValue("view") {
	case "connections":
		h.DeviceConnections(w, r)
	case "dns":
		h.DeviceDNS(w, r)
	case "alerts":
		h.DeviceAlerts(w, r)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

// SetLabels serves PUT /devices/{mac}/labels with body {"labels": [...]}.
// The body is capped at 16 KiB; labels at 32 of 1-64 printable bytes each.
func (h *Handler) SetLabels(w http.ResponseWriter, r *http.Request) {
	mac, ok := pathMAC(w, r)
	if !ok {
		return
	}

	var req struct {
		Labels []string `json:"labels"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLabelsBody)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Labels == nil {
		req.Labels = []string{}
	}

	device, err := h.store.SetLabels(mac, req.Labels)
	switch {
	case errors.Is(err, store.ErrInvalidLabels):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
		return
	case err != nil:
		slog.Error("set labels failed", "mac", mac, "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if h.OnLabels != nil {
		h.OnLabels(device)
	}
	writeJSON(w, http.StatusOK, device)
}
