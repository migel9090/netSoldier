//go:build integration

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	minioRootUser     = "netsoldier-test"
	minioRootPassword = "netsoldier-test-secret"
	coldBucket        = "netsoldier-cold"
)

// writeStorageXML mirrors the production storage.xml from
// deploy/kustomize/base/clickhouse/configmap.yaml, with the endpoint
// pointed at the `minio` network alias instead of minio.storage.svc.
func writeStorageXML(t *testing.T) string {
	t.Helper()
	xml := `<clickhouse>
    <storage_configuration>
        <disks>
            <s3_cold>
                <type>s3</type>
                <endpoint>http://minio:9000/netsoldier-cold/native/</endpoint>
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

func startMinIO(t *testing.T, networkName string) {
	t.Helper()
	ctx := context.Background()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: "minio/minio:RELEASE.2025-09-07T16-13-09Z",
			Cmd:   []string{"server", "/data", "--address", ":9000"},
			Env: map[string]string{
				"MINIO_ROOT_USER":     minioRootUser,
				"MINIO_ROOT_PASSWORD": minioRootPassword,
			},
			ExposedPorts:   []string{"9000/tcp"},
			Networks:       []string{networkName},
			NetworkAliases: map[string][]string{networkName: {"minio"}},
			WaitingFor:     wait.ForHTTP("/minio/health/live").WithPort("9000/tcp"),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start minio container: %v", err)
	}
	t.Cleanup(func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("terminate minio: %v", err)
		}
	})
}

// createColdBucket runs a one-shot `mc mb`, matching the production
// minio-bucket-init Job. A failure surfaces later as NoSuchBucket in the
// move/export subtests.
func createColdBucket(t *testing.T, networkName string) {
	t.Helper()
	ctx := context.Background()

	script := fmt.Sprintf(
		"mc alias set local http://minio:9000 %s %s && mc mb --ignore-existing local/%s",
		minioRootUser, minioRootPassword, coldBucket)

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:      "minio/mc:RELEASE.2025-08-13T08-35-41Z",
			Entrypoint: []string{"/bin/sh", "-c"},
			Cmd:        []string{script},
			Networks:   []string{networkName},
			WaitingFor: wait.ForExit().WithExitTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("run mc bucket init: %v", err)
	}
	t.Cleanup(func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("terminate mc: %v", err)
		}
	})
}

// TestClickHouseColdTier verifies step 119 end to end against real MinIO:
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

	startMinIO(t, net.Name)
	createColdBucket(t, net.Name)

	chURL := startClickHouseContainer(t, func(req *testcontainers.ContainerRequest) {
		req.Networks = []string{net.Name}
		req.Env["AWS_ACCESS_KEY_ID"] = minioRootUser
		req.Env["AWS_SECRET_ACCESS_KEY"] = minioRootPassword
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
		dest := fmt.Sprintf("http://minio:9000/%s/cold/network_flows/year=%s/month=%s/day=%s/network_flows.parquet",
			coldBucket, oldTS.Format("2006"), oldTS.Format("01"), oldTS.Format("02"))

		// Same query shape as export.sh in cold-export-cm.yaml.
		if err := chExec(chURL, fmt.Sprintf(
			"INSERT INTO FUNCTION s3('%s', '%s', '%s', 'Parquet') SELECT * FROM netsoldier.network_flows WHERE toDate(timestamp) = '%s'",
			dest, minioRootUser, minioRootPassword, day)); err != nil {
			t.Fatalf("parquet export: %v", err)
		}

		type countRow struct {
			Count json.Number `json:"c"`
		}
		var counts []countRow
		if err := chQueryRows(chURL, "netsoldier", fmt.Sprintf(
			"SELECT count() AS c FROM s3('%s', '%s', '%s', 'Parquet')",
			dest, minioRootUser, minioRootPassword), &counts); err != nil {
			t.Fatalf("parquet read-back: %v", err)
		}
		assertEq(t, "parquet archive rows", "3", counts[0].Count.String())
	})
}
