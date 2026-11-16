// Package agent is device-inventory's side of contract v2 section 8.1: the
// authenticated endpoint netagent posts captured frames to, the heartbeat
// state that /readyz and the capture metrics are derived from, and the queue
// of arp_probe commands handed back to the agent. device-inventory opens no
// socket and holds no capability; every frame is parsed here, inside the
// sandbox, by the pure parsers.
package agent

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/arp"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/dhcp"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/lldp"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/mdns"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/metrics"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/ssdp"
)

// maxBody is contract 8.1's 1 MiB request bound.
const maxBody = 1 << 20

// parser turns a captured frame into a sighting. Each protocol's parser is a
// pure function living in its own package; none opens a socket.
type parser func([]byte) (discovery.Sighting, error)

var parsers = map[string]parser{
	"arp":  arp.ParseFrame,
	"dhcp": dhcp.ParseFrame,
	"lldp": lldp.ParseFrame,
	"mdns": mdns.ParseFrame,
	"ssdp": ssdp.ParseFrame,
}

// Protocols lists the wire protocols the endpoint accepts, in a stable order.
func Protocols() []string {
	out := make([]string, 0, len(parsers))
	for k := range parsers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// frame mirrors contract 8.1's frame object.
type frame struct {
	T     int64  `json:"t"`
	Proto string `json:"proto"`
	Data  []byte `json:"data"`
}

type result struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

type status struct {
	Capture map[string]bool `json:"capture"`
	Dropped uint64          `json:"dropped"`
}

type batch struct {
	Agent     string   `json:"agent"`
	Interface string   `json:"interface"`
	Frames    []frame  `json:"frames"`
	Results   []result `json:"results"`
	Status    status   `json:"status"`
}

type command struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Target     string `json:"target,omitempty"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
}

// Ingestor accepts batches, dispatches frames to the parsers, and hands back
// arp_probe commands.
type Ingestor struct {
	token   string
	handle  func(discovery.Sighting)
	hb      *Heartbeat
	cmds    *CommandQueue
	badFrmt discovery.LogLimiter
}

// NewIngestor wires the endpoint to the sighting handler, the heartbeat
// tracker and the command queue. token is NETAGENT_TOKEN.
func NewIngestor(token string, handle func(discovery.Sighting), hb *Heartbeat, cmds *CommandQueue) *Ingestor {
	return &Ingestor{token: token, handle: handle, hb: hb, cmds: cmds,
		badFrmt: discovery.LogLimiter{Interval: 10 * time.Second}}
}

// Register mounts POST /agent/v1/frames. The route authenticates itself with
// the agent token rather than the device API key, so a leaked read key
// cannot be used to inject frames.
func (in *Ingestor) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /agent/v1/frames", in.serve)
}

func (in *Ingestor) serve(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if in.token == "" || !strings.HasPrefix(auth, prefix) ||
		subtle.ConstantTimeCompare([]byte(auth[len(prefix):]), []byte(in.token)) != 1 {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		http.Error(w, `{"error":"read failed"}`, http.StatusBadRequest)
		return
	}
	if len(body) > maxBody {
		http.Error(w, `{"error":"body exceeds 1 MiB"}`, http.StatusRequestEntityTooLarge)
		return
	}
	var b batch
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		// Be lenient on unknown fields so a newer agent can add to the
		// envelope, but reject outright garbage.
		if errors.Is(err, io.EOF) || !strings.Contains(err.Error(), "unknown field") {
			http.Error(w, `{"error":"malformed body"}`, http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(body, &b); err != nil {
			http.Error(w, `{"error":"malformed body"}`, http.StatusBadRequest)
			return
		}
	}

	in.ingest(b)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"commands": in.cmds.Take()})
}

func (in *Ingestor) ingest(b batch) {
	iface := discovery.SanitizeText(b.Interface, 32)
	for _, f := range b.Frames {
		parse, ok := parsers[f.Proto]
		if !ok {
			metrics.FramesRejected.WithLabelValues("unknown", "unknown_proto").Inc()
			continue
		}
		metrics.FramesReceived.WithLabelValues(f.Proto).Inc()
		s, err := parse(f.Data)
		if err != nil {
			metrics.FramesRejected.WithLabelValues(f.Proto, discovery.RejectReason(err)).Inc()
			if errors.Is(err, discovery.ErrLinkMismatch) {
				if ok, n := in.badFrmt.Allow(time.Now()); ok {
					slog.Warn("frame's payload claims a MAC that is not its link-layer source; ignored",
						"proto", f.Proto, "suppressed_since_last", n)
				}
			}
			continue
		}
		if f.Proto == "dhcp" {
			metrics.DHCPPackets.Inc()
		}
		if f.T > 0 {
			s.CapturedAt = time.Unix(0, f.T)
		}
		s.Interface = iface
		in.handle(s)
	}

	for _, res := range b.Results {
		if res.OK {
			slog.Debug("agent command succeeded", "id", res.ID)
			continue
		}
		slog.Warn("agent command failed", "id", res.ID, "error", discovery.SanitizeText(res.Error, 200))
	}

	in.hb.Observe(b.Agent, iface, b.Status.Capture, b.Status.Dropped)
}
