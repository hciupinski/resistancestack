package observability

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hciupinski/resistancestack/internal/config"
	"gopkg.in/yaml.v3"
)

const grafanaAssetsRemoteArchive = "/tmp/resistack-grafana-assets.tar.gz"

type GrafanaAssetBundle struct {
	Archive        []byte
	DashboardCount int
	AlertingCount  int
	Paths          []string
	Configured     bool
}

type grafanaAssetFile struct {
	absPath string
	relPath string
}

func BuildGrafanaAssetBundle(root string, cfg config.Config) (GrafanaAssetBundle, error) {
	base, configured, err := resolveGrafanaAssetsPath(root, cfg)
	if err != nil {
		return GrafanaAssetBundle{}, err
	}
	if !configured {
		return GrafanaAssetBundle{}, nil
	}

	files, dashboardCount, alertingCount, err := discoverGrafanaAssetFiles(base)
	if err != nil {
		return GrafanaAssetBundle{}, err
	}

	archive, err := archiveGrafanaAssetFiles(files)
	if err != nil {
		return GrafanaAssetBundle{}, err
	}

	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.relPath)
	}
	return GrafanaAssetBundle{
		Archive:        archive,
		DashboardCount: dashboardCount,
		AlertingCount:  alertingCount,
		Paths:          paths,
		Configured:     true,
	}, nil
}

func ValidateGrafanaAssetsPath(root string, cfg config.Config) error {
	_, err := BuildGrafanaAssetBundle(root, cfg)
	return err
}

func resolveGrafanaAssetsPath(root string, cfg config.Config) (string, bool, error) {
	raw := strings.TrimSpace(cfg.Observability.GrafanaAssetsPath)
	if raw == "" {
		return "", false, nil
	}
	if root == "" {
		root = "."
	}
	base := raw
	if !filepath.IsAbs(base) {
		base = filepath.Join(root, base)
	}
	cleaned, err := filepath.Abs(base)
	if err != nil {
		return "", true, fmt.Errorf("resolve observability.grafana_assets_path: %w", err)
	}
	info, err := os.Lstat(cleaned)
	if err != nil {
		return "", true, fmt.Errorf("observability.grafana_assets_path not found at %s", cleaned)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return "", true, fmt.Errorf("observability.grafana_assets_path must not be a symlink: %s", cleaned)
	}
	if !info.IsDir() {
		return "", true, fmt.Errorf("observability.grafana_assets_path must be a directory: %s", cleaned)
	}
	return cleaned, true, nil
}

func discoverGrafanaAssetFiles(base string) ([]grafanaAssetFile, int, int, error) {
	files := []grafanaAssetFile{}
	dashboardCount := 0
	alertingCount := 0

	err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == base {
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("grafana asset symlinks are not supported: %s", path)
		}
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return fmt.Errorf("resolve grafana asset path: %w", err)
		}
		rel = filepath.ToSlash(filepath.Clean(rel))
		if rel == "." || strings.HasPrefix(rel, "../") || strings.HasPrefix(rel, "/") {
			return fmt.Errorf("unsafe grafana asset path: %s", rel)
		}
		parts := strings.Split(rel, "/")
		if len(parts) == 0 || (parts[0] != "dashboards" && parts[0] != "alerting") {
			return fmt.Errorf("unsupported grafana asset path %q: expected dashboards/ or alerting/", rel)
		}
		if entry.IsDir() {
			return nil
		}

		switch parts[0] {
		case "dashboards":
			if strings.ToLower(filepath.Ext(rel)) != ".json" {
				return fmt.Errorf("unsupported dashboard asset %q: expected .json", rel)
			}
			if err := validateJSONFile(path); err != nil {
				return fmt.Errorf("invalid dashboard asset %q: %w", rel, err)
			}
			dashboardCount++
		case "alerting":
			ext := strings.ToLower(filepath.Ext(rel))
			switch ext {
			case ".json":
				if err := validateJSONFile(path); err != nil {
					return fmt.Errorf("invalid alerting asset %q: %w", rel, err)
				}
			case ".yaml", ".yml":
				if err := validateYAMLFile(path); err != nil {
					return fmt.Errorf("invalid alerting asset %q: %w", rel, err)
				}
			default:
				return fmt.Errorf("unsupported alerting asset %q: expected .yaml, .yml, or .json", rel)
			}
			alertingCount++
		}
		files = append(files, grafanaAssetFile{absPath: path, relPath: rel})
		return nil
	})
	if err != nil {
		return nil, 0, 0, err
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].relPath < files[j].relPath
	})
	return files, dashboardCount, alertingCount, nil
}

func validateJSONFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var payload any
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&payload); err != nil {
		return err
	}
	if decoder.Decode(&payload) != io.EOF {
		return fmt.Errorf("contains multiple JSON documents")
	}
	return nil
}

func validateYAMLFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	for {
		var node yaml.Node
		err := decoder.Decode(&node)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func archiveGrafanaAssetFiles(files []grafanaAssetFile) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	mtime := time.Unix(0, 0)

	for _, file := range files {
		info, err := os.Stat(file.absPath)
		if err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return nil, err
		}
		header := &tar.Header{
			Name:    file.relPath,
			Mode:    0o644,
			Size:    info.Size(),
			ModTime: mtime,
		}
		if err := tw.WriteHeader(header); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return nil, err
		}
		content, err := os.Open(file.absPath)
		if err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return nil, err
		}
		if _, err := io.Copy(tw, content); err != nil {
			_ = content.Close()
			_ = tw.Close()
			_ = gz.Close()
			return nil, err
		}
		if err := content.Close(); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		_ = gz.Close()
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
