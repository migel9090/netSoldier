package events

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// The JSON schemas in /schemas are the contract for anything that is not Go
// (the web-ui, ClickHouse ingestion, a third-party webhook receiver). The 1.x
// schema contradicted the struct for months because nothing compared them.
// These tests reflect over the struct tags and fail on any disagreement in
// field names, required-ness, JSON types, enums or patterns — in both
// directions — so the two can only change together.

// schemaNode is the subset of JSON Schema the contract schemas use.
type schemaNode struct {
	Type                 string                 `json:"type"`
	Format               string                 `json:"format"`
	Pattern              string                 `json:"pattern"`
	Enum                 []string               `json:"enum"`
	Minimum              *float64               `json:"minimum"`
	Maximum              *float64               `json:"maximum"`
	Required             []string               `json:"required"`
	Properties           map[string]*schemaNode `json:"properties"`
	Items                *schemaNode            `json:"items"`
	Ref                  string                 `json:"$ref"`
	Defs                 map[string]*schemaNode `json:"$defs"`
	AdditionalProperties *bool                  `json:"additionalProperties"`
}

func loadSchema(t *testing.T, name string) *schemaNode {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "schemas", name))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var n schemaNode
	if err := json.Unmarshal(raw, &n); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return &n
}

// schemaDiff compares Go types with a schema and collects every disagreement.
type schemaDiff struct {
	root     *schemaNode
	problems []string
}

func (d *schemaDiff) errorf(format string, args ...any) {
	d.problems = append(d.problems, fmt.Sprintf(format, args...))
}

func (d *schemaDiff) resolve(path string, n *schemaNode) *schemaNode {
	if n == nil {
		d.errorf("%s: no schema", path)
		return &schemaNode{}
	}
	if n.Ref == "" {
		return n
	}
	name, ok := strings.CutPrefix(n.Ref, "#/$defs/")
	if def := d.root.Defs[name]; ok && def != nil {
		return def
	}
	d.errorf("%s: unresolvable $ref %q", path, n.Ref)
	return &schemaNode{}
}

var timeType = reflect.TypeOf(time.Time{})

// jsonFields returns the struct's JSON field names and whether each is
// omitempty, in declaration order.
func jsonFields(typ reflect.Type) (names []string, omit map[string]bool, fields map[string]reflect.StructField) {
	omit = make(map[string]bool)
	fields = make(map[string]reflect.StructField)
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := f.Tag.Get("json")
		if !f.IsExported() || tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if name == "" {
			name = f.Name
		}
		names = append(names, name)
		omit[name] = slices.Contains(strings.Split(opts, ","), "omitempty")
		fields[name] = f
	}
	return names, omit, fields
}

func (d *schemaDiff) object(path string, typ reflect.Type, n *schemaNode) {
	n = d.resolve(path, n)
	if n.Type != "object" {
		d.errorf("%s: Go struct %s but schema type %q", path, typ, n.Type)
	}
	if n.AdditionalProperties == nil || *n.AdditionalProperties {
		d.errorf("%s: additionalProperties must be false, or a misspelt field validates", path)
	}

	names, omit, fields := jsonFields(typ)
	required := make(map[string]bool)
	for _, r := range n.Required {
		required[r] = true
		if _, ok := fields[r]; !ok {
			d.errorf("%s: schema requires %q, which the Go struct does not have", path, r)
		}
	}
	for _, name := range names {
		p := path + "." + name
		prop, ok := n.Properties[name]
		if !ok {
			d.errorf("%s: Go field missing from the schema", p)
			continue
		}
		switch {
		case !omit[name] && !required[name]:
			d.errorf("%s: always serialised by Go (no omitempty) but not required by the schema", p)
		case omit[name] && required[name]:
			d.errorf("%s: required by the schema but omitempty in Go", p)
		}
		d.value(p, fields[name].Type, prop)
	}
	for name := range n.Properties {
		if _, ok := fields[name]; !ok {
			d.errorf("%s.%s: in the schema but not in the Go struct", path, name)
		}
	}
}

func (d *schemaDiff) value(path string, typ reflect.Type, n *schemaNode) {
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	n = d.resolve(path, n)
	want := ""
	switch {
	case typ == timeType:
		want = "string"
		if n.Format != "date-time" {
			d.errorf("%s: time.Time needs format date-time, schema has %q", path, n.Format)
		}
	case typ.Kind() == reflect.String:
		want = "string"
	case typ.Kind() == reflect.Bool:
		want = "boolean"
	case typ.Kind() >= reflect.Int && typ.Kind() <= reflect.Uint64:
		want = "integer"
	case typ.Kind() == reflect.Slice:
		want = "array"
		if n.Items == nil {
			d.errorf("%s: array without items", path)
		} else {
			d.value(path+"[]", typ.Elem(), n.Items)
		}
	case typ.Kind() == reflect.Struct:
		d.object(path, typ, n)
		return
	default:
		d.errorf("%s: Go kind %s has no schema mapping in this test", path, typ.Kind())
		return
	}
	if n.Type != want {
		d.errorf("%s: Go %s is JSON %q, schema says %q", path, typ, want, n.Type)
	}
}

// enums collects every enum in the schema, keyed by its path.
func (d *schemaDiff) enums(path string, n *schemaNode, out map[string][]string) {
	n = d.resolve(path, n)
	if n.Enum != nil {
		out[path] = n.Enum
	}
	for name, p := range n.Properties {
		d.enums(path+"."+name, p, out)
	}
	if n.Items != nil {
		d.enums(path+"[]", n.Items, out)
	}
}

// compareEnums checks the schema's enums against the Go vocabularies, both
// ways: every schema enum must have a Go list, and the sets must be equal.
func (d *schemaDiff) compareEnums(goEnums map[string][]string) {
	found := make(map[string][]string)
	d.enums("", d.root, found)
	for path, schemaVals := range found {
		goVals, ok := goEnums[path]
		if !ok {
			d.errorf("%s: schema enum %v has no Go vocabulary in this test", path, schemaVals)
			continue
		}
		if a, b := sorted(schemaVals), sorted(goVals); !slices.Equal(a, b) {
			d.errorf("%s: schema enum %v, Go %v", path, a, b)
		}
	}
	for path := range goEnums {
		if _, ok := found[path]; !ok {
			d.errorf("%s: Go vocabulary has no enum in the schema", path)
		}
	}
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func (d *schemaDiff) report(t *testing.T) {
	t.Helper()
	for _, p := range d.problems {
		t.Error(p)
	}
}

func signalOnlyClasses() []string {
	var out []string
	for _, c := range knownSignalClasses {
		if c != SignalComposite {
			out = append(out, c)
		}
	}
	return out
}

func TestDetectionSchemaMatchesStruct(t *testing.T) {
	root := loadSchema(t, "detection-event.schema.json")
	d := &schemaDiff{root: root}
	d.object("", reflect.TypeOf(DetectionEvent{}), root)
	d.compareEnums(map[string][]string{
		".severity":        severities,
		".signal_class":    knownSignalClasses,
		".signals[].class": signalOnlyClasses(),
		".target.type":     targetTypes,
	})
	d.report(t)

	props := root.Properties
	if got := props["id"].Pattern; got != DetectionIDPattern {
		t.Errorf("id pattern: schema %q, Go %q", got, DetectionIDPattern)
	}
	if got := props["client_mac"].Pattern; got != MACPattern {
		t.Errorf("client_mac pattern: schema %q, Go %q", got, MACPattern)
	}
	checkVersionPattern(t, props["schema_version"].Pattern, DetectionSchemaVersion)
	checkConfidenceRange(t, "confidence", props["confidence"])
	checkConfidenceRange(t, "signals[].confidence", root.Defs["signal"].Properties["confidence"])
	if root.Properties["signals"].Items == nil || !slices.Contains(root.Required, "signals") {
		t.Error("signals must be a required array")
	}
}

func TestEnforcementSchemaMatchesStruct(t *testing.T) {
	root := loadSchema(t, "enforcement-action.schema.json")
	d := &schemaDiff{root: root}
	d.object("", reflect.TypeOf(EnforcementAction{}), root)
	d.compareEnums(map[string][]string{
		".action_type": actionTypes,
		".state":       enforcementStates,
	})
	d.report(t)
	checkVersionPattern(t, root.Properties["schema_version"].Pattern, EnforcementSchemaVersion)
}

func checkVersionPattern(t *testing.T, pattern, version string) {
	t.Helper()
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("schema_version pattern %q: %v", pattern, err)
	}
	if !re.MatchString(version) {
		t.Errorf("schema_version pattern %q does not accept the Go version %q", pattern, version)
	}
	major, _ := schemaMajor(version)
	if next := fmt.Sprintf("%d.0", major+1); re.MatchString(next) {
		t.Errorf("schema_version pattern %q accepts the next major %q", pattern, next)
	}
}

func checkConfidenceRange(t *testing.T, path string, n *schemaNode) {
	t.Helper()
	if n == nil || n.Minimum == nil || n.Maximum == nil || *n.Minimum != 0 || *n.Maximum != 100 {
		t.Errorf("%s: schema must bound confidence to 0-100 as Validate does", path)
	}
}

// TestSchemaDiffDetectsDrift proves the comparison above actually fails on
// each kind of drift, rather than passing because it checks nothing.
func TestSchemaDiffDetectsDrift(t *testing.T) {
	type inner struct {
		Kind string `json:"kind"`
	}
	type drifted struct {
		Renamed  string    `json:"renamed"`  // schema calls it "old_name"
		Optional string    `json:"optional"` // not omitempty, schema does not require it
		Count    string    `json:"count"`    // schema says integer
		Level    string    `json:"level"`
		When     time.Time `json:"when"` // schema lacks format date-time
		Items    []inner   `json:"items"`
	}
	f := false
	root := &schemaNode{
		Type:                 "object",
		AdditionalProperties: &f,
		Required:             []string{"renamed", "count", "level", "when", "items", "ghost"},
		Properties: map[string]*schemaNode{
			"old_name": {Type: "string"},
			"optional": {Type: "string"},
			"count":    {Type: "integer"},
			"level":    {Type: "string", Enum: []string{"a", "b"}},
			"when":     {Type: "string"},
			"items":    {Type: "array", Items: &schemaNode{Ref: "#/$defs/missing"}},
		},
	}
	d := &schemaDiff{root: root}
	d.object("", reflect.TypeOf(drifted{}), root)
	d.compareEnums(map[string][]string{".level": {"a", "c"}, ".absent": {"x"}})

	for _, want := range []string{
		".renamed: Go field missing from the schema",
		".old_name: in the schema but not in the Go struct",
		`schema requires "ghost"`,
		".optional: always serialised by Go",
		`.count: Go string is JSON "string", schema says "integer"`,
		".when: time.Time needs format date-time",
		`unresolvable $ref "#/$defs/missing"`,
		".level: schema enum [a b], Go [a c]",
		".absent: Go vocabulary has no enum in the schema",
	} {
		found := false
		for _, p := range d.problems {
			if strings.Contains(p, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("drift %q was not detected; problems: %v", want, d.problems)
		}
	}
}
