package observability

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
)

func TestBuildGrafanaAssetBundle_DiscoversAndArchivesAssets(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "observability", "grafana", "dashboards", "business.json"), `{"title":"Business"}`)
	writeTestFile(t, filepath.Join(root, "observability", "grafana", "alerting", "payments.yaml"), "apiVersion: 1\n")
	writeTestFile(t, filepath.Join(root, "observability", "grafana", "alerting", "nested", "policy.json"), `{"apiVersion":1}`)

	cfg := config.Default("demo")
	cfg.Observability.GrafanaAssetsPath = "./observability/grafana"

	bundle, err := BuildGrafanaAssetBundle(root, cfg)
	if err != nil {
		t.Fatalf("build grafana asset bundle: %v", err)
	}
	if !bundle.Configured {
		t.Fatal("expected configured bundle")
	}
	if bundle.DashboardCount != 1 {
		t.Fatalf("dashboard count = %d, want 1", bundle.DashboardCount)
	}
	if bundle.AlertingCount != 2 {
		t.Fatalf("alerting count = %d, want 2", bundle.AlertingCount)
	}
	wantPaths := []string{
		"alerting/nested/policy.json",
		"alerting/payments.yaml",
		"dashboards/business.json",
	}
	if !reflect.DeepEqual(bundle.Paths, wantPaths) {
		t.Fatalf("paths = %#v, want %#v", bundle.Paths, wantPaths)
	}
	if got := archivePaths(t, bundle.Archive); !reflect.DeepEqual(got, wantPaths) {
		t.Fatalf("archive paths = %#v, want %#v", got, wantPaths)
	}
}

func TestBuildGrafanaAssetBundle_RejectsInvalidDashboardJSON(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "grafana", "dashboards", "broken.json"), `{`)

	cfg := config.Default("demo")
	cfg.Observability.GrafanaAssetsPath = "grafana"

	_, err := BuildGrafanaAssetBundle(root, cfg)
	if err == nil || !strings.Contains(err.Error(), "invalid dashboard asset") {
		t.Fatalf("expected invalid dashboard error, got %v", err)
	}
}

func TestBuildGrafanaAssetBundle_RejectsSymlink(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "target.json"), `{"title":"Target"}`)
	if err := os.MkdirAll(filepath.Join(root, "grafana", "dashboards"), 0o755); err != nil {
		t.Fatalf("mkdir dashboards: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "target.json"), filepath.Join(root, "grafana", "dashboards", "linked.json")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	cfg := config.Default("demo")
	cfg.Observability.GrafanaAssetsPath = "grafana"

	_, err := BuildGrafanaAssetBundle(root, cfg)
	if err == nil || !strings.Contains(err.Error(), "symlinks are not supported") {
		t.Fatalf("expected symlink error, got %v", err)
	}
}

func TestBuildGrafanaAssetBundle_RejectsUnsupportedPath(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "grafana", "datasources", "loki.yaml"), "apiVersion: 1\n")

	cfg := config.Default("demo")
	cfg.Observability.GrafanaAssetsPath = "grafana"

	_, err := BuildGrafanaAssetBundle(root, cfg)
	if err == nil || !strings.Contains(err.Error(), "expected dashboards/ or alerting/") {
		t.Fatalf("expected unsupported path error, got %v", err)
	}
}

func writeTestFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func archivePaths(t *testing.T, archive []byte) []string {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("open gzip: %v", err)
	}
	defer reader.Close()

	tr := tar.NewReader(reader)
	paths := []string{}
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return paths
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		paths = append(paths, header.Name)
	}
}
