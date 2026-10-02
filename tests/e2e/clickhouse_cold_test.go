//go:build integration

package e2e

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	// Garage replaces MinIO here: MinIO withdrew its public `minio/minio`
	// and `minio/mc` images, so neither could be pulled any more and this
	// test could not start its S3 backend at all.
	garageImage = "dxflrs/garage:v2.4.1"

	garageKeyName = "netsoldier"

	coldBucket = "netsoldier-cold"
)

// garageCreds is the S3 key pair the test imports into Garage. Garage mints
// keys at runtime, but ClickHouse needs credentials in its environment
// before the bucket exists, so `garage key import` pins a known pair up
// front. They are generated per run rather than hardcoded: a fixed 64-char
// hex literal in the tree is indistinguishable from a real leaked key, both
// to a reader and to the secret scanner.
type garageCreds struct {
	accessKey string
	secretKey string
}

// newGarageCreds builds a key pair in the shape Garage expects: an access
// key id of "GK" plus 24 hex characters, and a 64 hex character secret.
func newGarageCreds(t *testing.T) garageCreds {
	t.Helper()
	return garageCreds{
		accessKey: "GK" + randomHex(t, 12),
		secretKey: randomHex(t, 32),
	}
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generate random credential: %v", err)
	}
	return hex.EncodeToString(b)
}

// writeGarageConfig renders the single-node Garage config. s3_region is
// pinned to us-east-1 because ClickHouse signs S3 requests for that region
// by default and Garage rejects a SigV4 signature scoped to anything else.
func writeGarageConfig(t *testing.T) string {
	t.Helper()
	cfg := `metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
db_engine = "sqlite"
replication_factor = 1

rpc_bind_addr = "[::]:3901"
rpc_secret = "0000000000000000000000000000000000000000000000000000000000000001"

[s3_api]
s3_region = "us-east-1"
api_bind_addr = "[::]:3900"

[admin]
api_bind_addr = "[::]:3903"
admin_token = "netsoldier-test-admin"
`
	path := filepath.Join(t.TempDir(), "garage.toml")
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write garage.toml: %v", err)
	}
	return path
}

// writeStorageXML mirrors the production storage.xml from
// deploy/kustomize/base/clickhouse/configmap.yaml, with the endpoint
// pointed at the `garage` network alias instead of garage.storage.svc.
func writeStorageXML(t *testing.T) string {
	t.Helper()
	xml := `<clickhouse>
    <storage_configuration>
        <disks>
            <s3_cold>
                <type>s3</type>
                <endpoint>http://garage:3900/netsoldier-cold/native/</endpoint>
                <use_environment_credentials>true</use_environment_credentials>
                <skip_access_check>true</skip_access_check>
                <metadata_path>/var/lib/clickhouse/disks/s3_cold/</metadata_path>
            </s3_cold>
        </disks>
        <policies>
            <tiered>
                <volumes>
                    <default>
                        <disk>default</disk>
                    </default>
                    <cold>
                        <disk>s3_cold</disk>
                        <perform_ttl_move_on_insert>false</perform_ttl_move_on_insert>
                    </cold>
                </volumes>
            </tiered>
        </policies>
    </storage_configuration>
</clickhouse>
`
	path := filepath.Join(t.TempDir(), "storage.xml")
	if err := os.WriteFile(path, []byte(xml), 0o644); err != nil {
		t.Fatalf("write storage.xml: %v", err)
	}
	return path
}

// startGarage brings up the S3 backend and bootstraps it: a fresh Garage
// node holds no cluster layout and serves no S3 traffic until one is
// applied, so the layout, the access key and the bucket are all created
// here. Mirrors the production bootstrap in
// deploy/kustomize/base/garage/bucket-init-job.yaml.
func startGarage(t *testing.T, networkName string) garageCreds {
	t.Helper()
	ctx := context.Background()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: garageImage,
			Files: []testcontainers.ContainerFile{{
				HostFilePath:      writeGarageConfig(t),
				ContainerFilePath: "/etc/garage.toml",
				FileMode:          0o644,
			}},
			ExposedPorts:   []string{"3900/tcp"},
			Networks:       []string{networkName},
			NetworkAliases: map[string][]string{networkName: {"garage"}},
			WaitingFor:     wait.ForLog("S3 API server listening"),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start garage container: %v", err)
	}
	t.Cleanup(func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("terminate garage: %v", err)
		}
	})

	// The image is built FROM scratch and has no shell, so each step runs
	// the static binary directly rather than through `sh -c`.
	garage := func(args ...string) string {
		t.Helper()
		code, reader, err := container.Exec(ctx, append([]string{"/garage"}, args...))
		out := ""
		if reader != nil {
			b, _ := io.ReadAll(reader)
			out = string(b)
		}
		if err != nil {
			t.Fatalf("garage %v: %v", args, err)
		}
		if code != 0 {
			t.Fatalf("garage %v: exit %d: %s", args, code, out)
		}
		return out
	}

	// `node id -q` still prefixes the id with docker-exec framing bytes;
	// pull the 64-char hex key out rather than trusting the raw output.
	nodeID := parseNodeID(t, garage("node", "id", "-q"))

	creds := newGarageCreds(t)

	garage("layout", "assign", "-z", "dc1", "-c", "20G", nodeID)
	garage("layout", "apply", "--version", "1")
	garage("key", "import", "--yes", creds.accessKey, creds.secretKey, "-n", garageKeyName)
	garage("bucket", "create", coldBucket)
	garage("bucket", "allow", "--read", "--write", "--owner", coldBucket, "--key", garageKeyName)

	return creds
}

// parseNodeID extracts the hex node id from `garage node id -q` output.
func parseNodeID(t *testing.T, out string) string {
	t.Helper()
	re := regexp.MustCompile(`[0-9a-f]{64}`)
	id := re.FindString(out)
	if id == "" {
		t.Fatalf("no node id in garage output: %q", out)
	}
	return id
}

// TestClickHouseColdTier verifies step 119 end to end against a real S3
// backend (Garage):
// migration 018 switches tables to the tiered policy, aged parts move to
// the S3 cold volume, historical queries transparently read them back, and
// the Parquet cold-export path (export.sh) round-trips through s3().
func TestClickHouseColdTier(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ctx := context.Background()

	net, err := network.New(ctx)
	if err != nil {
		t.Fatalf("create docker network: %v", err)
	}
	t.Cleanup(func() {
		if err := net.Remove(context.Background()); err != nil {
			t.Logf("remove network: %v", err)
		}
	})

	creds := startGarage(t, net.Name)

	chURL := startClickHouseContainer(t, func(req *testcontainers.ContainerRequest) {
		req.Networks = []string{net.Name}
		req.Env["AWS_ACCESS_KEY_ID"] = creds.accessKey
		req.Env["AWS_SECRET_ACCESS_KEY"] = creds.secretKey
	})
	runMigrations(t, chURL)

	t.Run("TieredPolicyApplied", func(t *testing.T) {
		type row struct {
			Policy string `json:"storage_policy"`
		}
		var rows []row
		if err := chQueryRows(chURL, "netsoldier",
			"SELECT storage_policy FROM system.tables WHERE database = 'netsoldier' AND name = 'network_flows'",
			&rows); err != nil {
			t.Fatalf("query storage_policy: %v", err)
		}
		if len(rows) != 1 || rows[0].Policy != "tiered" {
			t.Fatalf("network_flows storage_policy = %v, want tiered", rows)
		}

		type volRow struct {
			Volume string `json:"volume_name"`
		}
		var vols []volRow
		if err := chQueryRows(chURL, "netsoldier",
			"SELECT volume_name FROM system.storage_policies WHERE policy_name = 'tiered' ORDER BY volume_priority",
			&vols); err != nil {
			t.Fatalf("query storage_policies: %v", err)
		}
		if len(vols) != 2 || vols[0].Volume != "default" || vols[1].Volume != "cold" {
			t.Fatalf("tiered policy volumes = %v, want [default cold]", vols)
		}
	})

	// Merges could combine hot and aged parts before the move assertion runs.
	if err := chExec(chURL, "SYSTEM STOP MERGES netsoldier.network_flows"); err != nil {
		t.Fatalf("stop merges: %v", err)
	}

	oldTS := time.Now().UTC().AddDate(0, 0, -45)
	insertFlow := func(ts time.Time, dstIP string) {
		t.Helper()
		if err := chInsert(chURL, "netsoldier", "network_flows", map[string]any{
			"timestamp":   ts.Format("2006-01-02 15:04:05"),
			"src_ip":      "192.168.1.50",
			"src_port":    40000,
			"dst_ip":      dstIP,
			"dst_port":    443,
			"protocol":    6,
			"bytes_in":    512,
			"bytes_out":   2048,
			"packets_in":  4,
			"packets_out": 6,
			"duration_ms": 120,
			"tcp_flags":   24,
			"vlan_id":     0,
		}); err != nil {
			t.Fatalf("insert flow: %v", err)
		}
	}

	const oldRows, recentRows = 3, 2
	for i := 0; i < oldRows; i++ {
		insertFlow(oldTS.Add(time.Duration(i)*time.Minute), "203.0.113.7")
	}

	t.Run("HistoricalQueryFromColdVolume", func(t *testing.T) {
		// The background TTL move may race the explicit MOVE; retry, then
		// assert on the part placement, which both paths converge on.
		var moveErr error
		for attempt := 0; attempt < 3; attempt++ {
			if moveErr = chExec(chURL,
				"ALTER TABLE netsoldier.network_flows MOVE PARTITION ID 'all' TO VOLUME 'cold'"); moveErr == nil {
				break
			}
			time.Sleep(2 * time.Second)
		}
		if moveErr != nil {
			t.Logf("explicit MOVE failed (background TTL move may cover it): %v", moveErr)
		}

		for i := 0; i < recentRows; i++ {
			insertFlow(time.Now().UTC(), "198.51.100.9")
		}

		type diskRow struct {
			Disk string      `json:"disk_name"`
			Rows json.Number `json:"total_rows"`
		}
		deadline := time.Now().Add(120 * time.Second)
		for {
			var disks []diskRow
			if err := chQueryRows(chURL, "netsoldier",
				"SELECT disk_name, sum(rows) AS total_rows FROM system.parts WHERE database = 'netsoldier' AND table = 'network_flows' AND active GROUP BY disk_name ORDER BY disk_name",
				&disks); err != nil {
				t.Fatalf("query parts: %v", err)
			}
			byDisk := map[string]string{}
			for _, d := range disks {
				byDisk[d.Disk] = d.Rows.String()
			}
			if byDisk["s3_cold"] == "3" && byDisk["default"] == "2" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("parts never reached cold tier, distribution: %v", byDisk)
			}
			time.Sleep(2 * time.Second)
		}

		type countRow struct {
			Count json.Number `json:"c"`
		}
		var counts []countRow
		if err := chQueryRows(chURL, "netsoldier",
			"SELECT count() AS c FROM network_flows WHERE timestamp < now() - INTERVAL 40 DAY",
			&counts); err != nil {
			t.Fatalf("historical count: %v", err)
		}
		assertEq(t, "historical rows (read from S3)", "3", counts[0].Count.String())

		type flowRow struct {
			DstIP string `json:"dst_ip"`
		}
		var flows []flowRow
		if err := chQueryRows(chURL, "netsoldier",
			"SELECT DISTINCT dst_ip FROM network_flows WHERE timestamp < now() - INTERVAL 40 DAY",
			&flows); err != nil {
			t.Fatalf("historical select: %v", err)
		}
		if len(flows) != 1 || flows[0].DstIP != "203.0.113.7" {
			t.Fatalf("historical dst_ip = %v, want [203.0.113.7]", flows)
		}
	})

	t.Run("ParquetArchiveRoundtrip", func(t *testing.T) {
		day := oldTS.Format("2006-01-02")
		dest := fmt.Sprintf("http://garage:3900/%s/cold/network_flows/year=%s/month=%s/day=%s/network_flows.parquet",
			coldBucket, oldTS.Format("2006"), oldTS.Format("01"), oldTS.Format("02"))

		// Same query shape as export.sh in cold-export-cm.yaml.
		if err := chExec(chURL, fmt.Sprintf(
			"INSERT INTO FUNCTION s3('%s', '%s', '%s', 'Parquet') SELECT * FROM netsoldier.network_flows WHERE toDate(timestamp) = '%s'",
			dest, creds.accessKey, creds.secretKey, day)); err != nil {
			t.Fatalf("parquet export: %v", err)
		}

		type countRow struct {
			Count json.Number `json:"c"`
		}
		var counts []countRow
		if err := chQueryRows(chURL, "netsoldier", fmt.Sprintf(
			"SELECT count() AS c FROM s3('%s', '%s', '%s', 'Parquet')",
			dest, creds.accessKey, creds.secretKey), &counts); err != nil {
			t.Fatalf("parquet read-back: %v", err)
		}
		assertEq(t, "parquet archive rows", "3", counts[0].Count.String())
	})
}
