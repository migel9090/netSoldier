package ioc

import (
	"fmt"

	"github.com/migel9090/netSoldier/libs/indicator"
)

// Validate normalizes an indicator and reports why it cannot be used.
// Rejected indicators are dropped at ingest rather than stored, so a single
// malformed feed row cannot propagate to every downstream export.
//
// The value rules live in libs/indicator, which the detection-engine's
// matcher also applies at its boundary: one allow-list on both sides, so
// they can no longer drift apart the way the two hand-written deny-lists
// did. Free-text fields are cleaned here too — a tab and a newline in
// Threat or Reference used to inject whole lines into the Zeek Intel file.
func Validate(i Indicator) (Indicator, error) {
	v, err := indicator.Value(i.Type, i.Value)
	if err != nil {
		return i, err
	}
	i.Value = v

	if i.Confidence < 0 || i.Confidence > 100 {
		return i, fmt.Errorf("confidence %d out of range", i.Confidence)
	}
	i.Source = indicator.Text(i.Source, indicator.MaxSourceLen)
	i.Threat = indicator.Text(i.Threat, indicator.MaxTextLen)
	i.Reference = indicator.Text(i.Reference, indicator.MaxReferenceLen)
	i.Tags = indicator.Tags(i.Tags)
	return i, nil
}
