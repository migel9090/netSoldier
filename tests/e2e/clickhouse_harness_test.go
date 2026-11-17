//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.yaml.in/yaml/v3"
)

// The deployment's ClickHouse, as the tests run it: the image the
// StatefulSet pins, the server and user configuration from
// deploy/kustomize/base/clickhouse/configmap.yaml with the placeholders the
// init container fills (account password hashes, the pod network) filled for
// the test, and the schema applied by deploy/clickhouse/migrate.sh running as
// the migrate account — the clickhouse-migrate Job's path. Every client then
// talks to it with its own account, so a grant that is missing (or one too
// many) fails here instead of in the lab.

// chServer is one such server.
type chServer struct {
	URL       string // http://host:port of the HTTP interface
	container testcontainers.Container
	passwords map[string]string // account -> password
}

// chOptions changes how the server starts; the zero value is the deployment.
type chOptions struct {
	// customize edits the container request (networks, environment).
	customize func(*testcontainers.ContainerRequest)
	// noMigrate leaves the schema to the test.
	noMigrate bool
}

const (
	chConfigMap   = "deploy/kustomize/base/clickhouse/configmap.yaml"
	chStatefulSet = "deploy/kustomize/base/clickhouse/statefulset.yaml"
	migrateDir    = "/opt/migrate" // where migrate.sh and migrations/ are copied
)

// clickhouseImage is the server image the StatefulSet runs, digest included.
func clickhouseImage(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), chStatefulSet))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s+image:\s*(clickhouse/clickhouse-server:\S+)\s*$`).FindSubmatch(raw)
	if m == nil {
		t.Fatalf("%s names no clickhouse/clickhouse-server image", chStatefulSet)
	}
	return string(m[1])
}

// clickhouseConfig returns the ConfigMap's files.
func clickhouseConfig(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), chConfigMap))
	if err != nil {
		t.Fatal(err)
	}
	var cm struct {
		Data map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal(raw, &cm); err != nil {
		t.Fatalf("%s: %v", chConfigMap, err)
	}
	for _, k := range []string{"users-override.xml", "memory-limits.xml", "storage.xml"} {
		if cm.Data[k] == "" {
			t.Fatalf("%s has no %s", chConfigMap, k)
		}
	}
	return cm.Data
}

var passwordPlaceholder = regexp.MustCompile(`__([A-Z0-9_]+)_PASSWORD_SHA256__`)

// renderUsers fills users-override.xml the way the StatefulSet's init
// container does: a SHA-256 per account (of a random password generated
// here) and the pod network, which for the test is every address — the
// server is reached through a published port.
func renderUsers(t *testing.T, tmpl string) (string, map[string]string) {
	t.Helper()
	passwords := map[string]string{}
	out := passwordPlaceholder.ReplaceAllStringFunc(tmpl, func(ph string) string {
		account := strings.ToLower(passwordPlaceholder.FindStringSubmatch(ph)[1])
		pw, ok := passwords[account]
		if !ok {
			b := make([]byte, 16)
			if _, err := rand.Read(b); err != nil {
				t.Fatal(err)
			}
			pw = hex.EncodeToString(b)
			passwords[account] = pw
		}
		sum := sha256.Sum256([]byte(pw))
		return hex.EncodeToString(sum[:])
	})
	out = strings.ReplaceAll(out, "__POD_CIDR__", "::/0")
	if left := regexp.MustCompile(`__[A-Z0-9_]+__`).FindString(out); left != "" {
		t.Fatalf("users-override.xml: placeholder %s is not filled by the test (the init container would refuse it too)", left)
	}
	return out, passwords
}

// startProdClickHouse starts the server and, unless opts.noMigrate, applies
// every migration with migrate.sh as the migrate account.
func startProdClickHouse(t *testing.T, opts chOptions) *chServer {
	t.Helper()
	ctx := context.Background()
	root := repoRoot(t)
	cfg := clickhouseConfig(t)
	users, passwords := renderUsers(t, cfg["users-override.xml"])

	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	files := []testcontainers.ContainerFile{
		{HostFilePath: write("users-override.xml", users), ContainerFilePath: "/etc/clickhouse-server/users.d/users-override.xml", FileMode: 0o644},
		{HostFilePath: write("memory-limits.xml", cfg["memory-limits.xml"]), ContainerFilePath: "/etc/clickhouse-server/config.d/memory-limits.xml", FileMode: 0o644},
		{HostFilePath: write("storage.xml", cfg["storage.xml"]), ContainerFilePath: "/etc/clickhouse-server/config.d/storage.xml", FileMode: 0o644},
		{HostFilePath: filepath.Join(root, "deploy/clickhouse/migrate.sh"), ContainerFilePath: migrateDir + "/migrate.sh", FileMode: 0o755},
	}
	for _, name := range migrationFiles(t) {
		files = append(files, testcontainers.ContainerFile{
			HostFilePath:      filepath.Join(root, "deploy/clickhouse/migrations", name),
			ContainerFilePath: migrateDir + "/migrations/" + name, FileMode: 0o644})
	}

	req := testcontainers.ContainerRequest{
		Image:        clickhouseImage(t),
		ExposedPorts: []string{"8123/tcp"},
		// Like the StatefulSet: no CLICKHOUSE_USER/PASSWORD/DB, which would
		// make the image's entrypoint replace `default` with an open account.
		Env:        map[string]string{},
		Files:      files,
		WaitingFor: wait.ForHTTP("/ping").WithPort("8123/tcp").WithStartupTimeout(2 * time.Minute),
	}
	if opts.customize != nil {
		opts.customize(&req)
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	if err != nil {
		t.Fatalf("start clickhouse: %v", err)
	}
	t.Cleanup(func() {
		if err := c.Terminate(context.Background()); err != nil {
			t.Logf("terminate clickhouse: %v", err)
		}
	})
	host, err := c.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := c.MappedPort(ctx, "8123/tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := &chServer{URL: fmt.Sprintf("http://%s:%s", host, port.Port()), container: c, passwords: passwords}
	if !opts.noMigrate {
		if out, code := s.migrate(t, "", "apply"); code != 0 {
			t.Fatalf("migrate.sh as migrate: exit %d\n%s", code, out)
		}
	}
	return s
}

// migrationFiles lists deploy/clickhouse/migrations/*.sql in order.
func migrationFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(repoRoot(t), "deploy", "clickhouse", "migrations"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// migrate runs migrate.sh inside the server's container as the migrate
// account, the way the Job runs it (native protocol, password from the
// environment). dir is a MIGRATIONS_DIR inside the container ("" for all of
// them). It returns the combined output and the exit code.
func (s *chServer) migrate(t *testing.T, dir, mode string) (string, int) {
	t.Helper()
	env := []string{"CLICKHOUSE_HOST=127.0.0.1", "CLICKHOUSE_USER=migrate",
		"CLICKHOUSE_PASSWORD=" + s.passwords["migrate"], "MIGRATE_WAIT_SECONDS=60"}
	if dir != "" {
		env = append(env, "MIGRATIONS_DIR="+dir)
	}
	return s.containerExec(t, env, "sh", migrateDir+"/migrate.sh", mode)
}

// migrateOnly applies the migrations keep selects (and every one before
// them that is not applied yet must be selected too: migrate.sh refuses to
// apply out of order).
func (s *chServer) migrateOnly(t *testing.T, keep func(name string) bool) {
	t.Helper()
	dir := fmt.Sprintf("/tmp/migrations-%d", time.Now().UnixNano())
	cmd := "mkdir -p " + dir
	for _, name := range migrationFiles(t) {
		if keep(name) {
			cmd += " && cp " + migrateDir + "/migrations/" + name + " " + dir + "/"
		}
	}
	if out, code := s.containerExec(t, nil, "sh", "-c", cmd); code != 0 {
		t.Fatalf("stage migrations: exit %d: %s", code, out)
	}
	if out, code := s.migrate(t, dir, "apply"); code != 0 {
		t.Fatalf("migrate.sh: exit %d\n%s", code, out)
	}
}

// containerExec runs a command in the server's container.
func (s *chServer) containerExec(t *testing.T, env []string, cmd ...string) (string, int) {
	t.Helper()
	opts := []tcexec.ProcessOption{tcexec.Multiplexed()}
	if len(env) > 0 {
		opts = append(opts, tcexec.WithEnv(env))
	}
	code, r, err := s.container.Exec(context.Background(), cmd, opts...)
	if err != nil {
		t.Fatalf("exec %v: %v", cmd, err)
	}
	out, _ := io.ReadAll(r)
	return string(out), code
}

// admin runs a statement as the local break-glass account `default`, which
// only accepts connections from inside the container: for what no service
// account may do (OPTIMIZE, SYSTEM).
func (s *chServer) admin(t *testing.T, query string) string {
	t.Helper()
	out, code := s.containerExec(t, []string{"CLICKHOUSE_PASSWORD=" + s.passwords["default"]},
		"clickhouse-client", "--user", "default", "--query", query)
	if code != 0 {
		t.Fatalf("%s as default: exit %d: %s", query, code, out)
	}
	return withoutAllocatorNotes(out)
}

// withoutAllocatorNotes drops the line jemalloc writes to stderr in some
// containers ("<jemalloc>: Number of CPUs detected is not deterministic"),
// which the exec stream interleaves with the client's output.
func withoutAllocatorNotes(out string) string {
	var kept []string
	for _, l := range strings.Split(out, "\n") {
		if !strings.HasPrefix(l, "<jemalloc>") {
			kept = append(kept, l)
		}
	}
	return strings.Join(kept, "\n")
}

// do sends one request as account.
func (s *chServer) do(account, query string, body []byte) ([]byte, error) {
	pw, ok := s.passwords[account]
	if !ok {
		return nil, fmt.Errorf("no account %q in users-override.xml", account)
	}
	q := url.Values{"database": {"netsoldier"}}
	var rd io.Reader = strings.NewReader(query)
	if body != nil {
		q.Set("query", query)
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(http.MethodPost, s.URL+"/?"+q.Encode(), rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-ClickHouse-User", account)
	req.Header.Set("X-ClickHouse-Key", pw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("clickhouse %d as %s: %s", resp.StatusCode, account, bytes.TrimSpace(out))
	}
	return out, nil
}

// exec runs a statement as account.
func (s *chServer) exec(account, query string) error {
	_, err := s.do(account, query, nil)
	return err
}

// insert writes rows (JSONEachRow) to table as account.
func (s *chServer) insert(account, table string, rows ...any) error {
	var buf bytes.Buffer
	for _, r := range rows {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	_, err := s.do(account, "INSERT INTO "+table+" FORMAT JSONEachRow", buf.Bytes())
	return err
}

// query runs a SELECT as account and decodes the rows into dest.
func (s *chServer) query(account, query string, dest any) error {
	out, err := s.do(account, query+" FORMAT JSON", nil)
	if err != nil {
		return err
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(out, &envelope); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return json.Unmarshal(envelope.Data, dest)
}

// mustInsert is insert that fails the test.
func (s *chServer) mustInsert(t *testing.T, account, table string, rows ...any) {
	t.Helper()
	if err := s.insert(account, table, rows...); err != nil {
		t.Fatalf("insert into %s as %s: %v", table, account, err)
	}
}

// count returns the number of rows a SELECT count() query gives, as account.
func (s *chServer) count(t *testing.T, account, query string) int {
	t.Helper()
	var rows []struct {
		N json.Number `json:"n"`
	}
	if err := s.query(account, query, &rows); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	if len(rows) != 1 {
		t.Fatalf("%s: %d rows", query, len(rows))
	}
	n, _ := rows[0].N.Int64()
	return int(n)
}
