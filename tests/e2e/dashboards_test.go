//go:build e2e || integration

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// The Grafana dashboards are ConfigMaps under the observability base, one
// dashboard JSON per data key. dashboardQueries reads every ClickHouse query
// out of them — panel targets, panels nested in rows, template variables —
// so a panel added later is checked without anyone listing it.

const dashboardDir = "deploy/kustomize/base/observability"

// clickhouseDatasource is the Grafana plugin id of the ClickHouse
// datasource the dashboards use.
const clickhouseDatasource = "grafana-clickhouse-datasource"

// panelQuery is one ClickHouse query of one dashboard.
type panelQuery struct {
	File  string // ConfigMap file
	UID   string // dashboard uid
	Panel string // panel title, or "var <name>" for a template variable
	ID    int
	SQL   string
}

func (q panelQuery) key() string { return q.UID + "/" + q.Panel }

func (q panelQuery) String() string {
	return fmt.Sprintf("%s panel %d %q", q.File, q.ID, q.Panel)
}

type grafanaDatasource struct {
	Type string `json:"type"`
}

type grafanaPanel struct {
	ID         int                `json:"id"`
	Title      string             `json:"title"`
	Datasource *grafanaDatasource `json:"datasource"`
	Targets    []struct {
		Datasource *grafanaDatasource `json:"datasource"`
		RawSQL     string             `json:"rawSql"`
		Expr       string             `json:"expr"`
		RefID      string             `json:"refId"`
	} `json:"targets"`
	Panels []grafanaPanel `json:"panels"`
}

type grafanaDashboard struct {
	UID        string         `json:"uid"`
	Panels     []grafanaPanel `json:"panels"`
	Templating struct {
		List []struct {
			Name       string             `json:"name"`
			Type       string             `json:"type"`
			Datasource *grafanaDatasource `json:"datasource"`
			Query      json.RawMessage    `json:"query"`
		} `json:"list"`
	} `json:"templating"`
}

// dashboardQueries returns every ClickHouse query of every dashboard. It
// fails the test on a dashboard it cannot read and on a ClickHouse target
// without SQL: either would let a broken panel pass unnoticed.
func dashboardQueries(t *testing.T) []panelQuery {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(repoRoot(t), dashboardDir, "grafana-*-cm.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no dashboard ConfigMaps under %s (%v)", dashboardDir, err)
	}
	sort.Strings(files)
	var out []panelQuery
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var cm struct {
			Data map[string]string `yaml:"data"`
		}
		if err := yaml.Unmarshal(raw, &cm); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		name := filepath.Base(f)
		for key, body := range cm.Data {
			var d grafanaDashboard
			if err := json.Unmarshal([]byte(body), &d); err != nil {
				t.Fatalf("%s: %s is not valid dashboard JSON: %v", name, key, err)
			}
			out = append(out, panelQueriesOf(t, name, d.UID, d.Panels, nil)...)
			for _, v := range d.Templating.List {
				if v.Type != "query" || v.Datasource == nil || v.Datasource.Type != clickhouseDatasource {
					continue
				}
				var sql string
				if err := json.Unmarshal(v.Query, &sql); err != nil {
					var obj struct {
						RawSQL string `json:"rawSql"`
						Query  string `json:"query"`
					}
					if err := json.Unmarshal(v.Query, &obj); err != nil {
						t.Fatalf("%s: variable %s: unreadable query %s", name, v.Name, v.Query)
					}
					sql = obj.RawSQL + obj.Query
				}
				if strings.TrimSpace(sql) == "" {
					t.Fatalf("%s: variable %s has no query", name, v.Name)
				}
				out = append(out, panelQuery{File: name, UID: d.UID, Panel: "var " + v.Name, SQL: sql})
			}
		}
	}
	return out
}

func panelQueriesOf(t *testing.T, file, uid string, panels []grafanaPanel, parent *grafanaDatasource) []panelQuery {
	t.Helper()
	var out []panelQuery
	for _, p := range panels {
		ds := p.Datasource
		if ds == nil {
			ds = parent
		}
		out = append(out, panelQueriesOf(t, file, uid, p.Panels, ds)...)
		for _, tg := range p.Targets {
			tds := tg.Datasource
			if tds == nil {
				tds = ds
			}
			if tds == nil {
				t.Fatalf("%s panel %d %q: target %s has no datasource", file, p.ID, p.Title, tg.RefID)
			}
			switch tds.Type {
			case clickhouseDatasource:
				if strings.TrimSpace(tg.RawSQL) == "" {
					t.Fatalf("%s panel %d %q: ClickHouse target %s has no rawSql", file, p.ID, p.Title, tg.RefID)
				}
				out = append(out, panelQuery{File: file, UID: uid, Panel: p.Title, ID: p.ID, SQL: tg.RawSQL})
			case "prometheus":
				// PromQL; not ClickHouse.
			default:
				t.Fatalf("%s panel %d %q: datasource type %q is neither ClickHouse nor Prometheus; "+
					"teach this test how to check it", file, p.ID, p.Title, tds.Type)
			}
		}
	}
	return out
}

var (
	macroTimeFilter   = regexp.MustCompile(`\$__timeFilter\(([^)]*)\)`)
	macroTimeInterval = regexp.MustCompile(`\$__timeInterval\(([^)]*)\)`)
	anyMacro          = regexp.MustCompile(`\$__\w+`)
	templateVar       = regexp.MustCompile(`\$\{(\w+)\}|\$(\w+)`)
)

// expandMacros does what the Grafana ClickHouse plugin does to a query
// before sending it, for the time range [from, to] and the template
// variables vars. A macro or variable it does not know is an error, so a
// panel using a new one is noticed rather than sent half-expanded.
func expandMacros(sql string, from, to time.Time, vars map[string]string) (string, error) {
	f, u := from.Unix(), to.Unix()
	sql = macroTimeFilter.ReplaceAllStringFunc(sql, func(m string) string {
		col := strings.TrimSpace(macroTimeFilter.FindStringSubmatch(m)[1])
		return fmt.Sprintf("%s >= toDateTime(%d) AND %s <= toDateTime(%d)", col, f, col, u)
	})
	sql = macroTimeInterval.ReplaceAllStringFunc(sql, func(m string) string {
		col := strings.TrimSpace(macroTimeInterval.FindStringSubmatch(m)[1])
		return fmt.Sprintf("toStartOfInterval(toDateTime(%s), INTERVAL 60 second)", col)
	})
	sql = strings.ReplaceAll(sql, "$__fromTime", fmt.Sprintf("toDateTime(%d)", f))
	sql = strings.ReplaceAll(sql, "$__toTime", fmt.Sprintf("toDateTime(%d)", u))
	if m := anyMacro.FindString(sql); m != "" {
		return "", fmt.Errorf("unknown Grafana macro %s", m)
	}
	var unknown string
	sql = templateVar.ReplaceAllStringFunc(sql, func(m string) string {
		sm := templateVar.FindStringSubmatch(m)
		name := sm[1] + sm[2]
		v, ok := vars[name]
		if !ok {
			unknown = name
		}
		return v
	})
	if unknown != "" {
		return "", fmt.Errorf("unknown template variable $%s", unknown)
	}
	return sql, nil
}

// TestDashboardQueriesAreReadable is the part that needs no server: every
// dashboard parses, every ClickHouse target has SQL, and every macro and
// variable in it is one the query test knows how to expand.
func TestDashboardQueriesAreReadable(t *testing.T) {
	qs := dashboardQueries(t)
	if len(qs) < 70 {
		t.Fatalf("%d ClickHouse queries found in the dashboards; there were 78 when this test was written, "+
			"so the extraction has broken", len(qs))
	}
	now := time.Now()
	for _, q := range qs {
		if _, err := expandMacros(q.SQL, now.Add(-time.Hour), now, dashboardVars); err != nil {
			t.Errorf("%s: %v", q, err)
		}
	}
}

// dashboardVars are the template variables the dashboards define, at the
// value that selects everything.
var dashboardVars = map[string]string{
	"src_ip": "",
}
