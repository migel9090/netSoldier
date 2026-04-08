package correlator

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// DeviceCache periodically fetches the device inventory and provides
// fast IP-to-device lookups for flow correlation.
type DeviceCache struct {
	url  string
	http *http.Client

	mu   sync.RWMutex
	byIP map[string]DeviceInfo
}

func NewDeviceCache(inventoryURL string) *DeviceCache {
	return &DeviceCache{
		url:  inventoryURL,
		http: &http.Client{Timeout: 5 * time.Second},
		byIP: make(map[string]DeviceInfo),
	}
}

// RefreshLoop periodically fetches the device list from device-inventory.
func (c *DeviceCache) RefreshLoop(ctx context.Context, interval time.Duration) {
	c.refresh(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.refresh(ctx)
		}
	}
}

func (c *DeviceCache) refresh(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+"/devices", nil)
	if err != nil {
		return
	}
	resp, err := c.http.Do(req)
	if err != nil {
		slog.Debug("device cache refresh failed", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	var devices []DeviceInfo
	if err := json.NewDecoder(resp.Body).Decode(&devices); err != nil {
		slog.Debug("device cache decode failed", "error", err)
		return
	}

	byIP := make(map[string]DeviceInfo, len(devices))
	for _, d := range devices {
		if d.IP != "" {
			byIP[d.IP] = d
		}
	}

	c.mu.Lock()
	c.byIP = byIP
	c.mu.Unlock()

	slog.Debug("device cache refreshed", "devices", len(byIP))
}

// Lookup returns device info for an IP, or an empty DeviceInfo if not found.
func (c *DeviceCache) Lookup(ip string) DeviceInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.byIP[ip]
}
