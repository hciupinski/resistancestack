package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var envNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

func Save(path string, cfg Config) error {
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func SaveDocument(path string, doc *yaml.Node) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer file.Close()

	encoder := yaml.NewEncoder(file)
	encoder.SetIndent(2)
	if err := encoder.Encode(doc); err != nil {
		_ = encoder.Close()
		return fmt.Errorf("encode %s: %w", path, err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("close encoder for %s: %w", path, err)
	}
	return nil
}

func Load(path string) (Config, error) {
	cfg, _, err := LoadWithEnv(path, "")
	return cfg, err
}

func LoadWithEnv(path string, env string) (Config, string, error) {
	env = strings.TrimSpace(env)
	if err := ValidateEnvName(env); err != nil {
		return Config{}, "", err
	}

	cfg := Default("resistack")
	if err := loadInto(&cfg, path); err != nil {
		return Config{}, "", err
	}

	overlayPath := ""
	if env != "" {
		overlayPath = overlayPathForEnv(path, env)
		if _, err := os.Stat(overlayPath); err != nil {
			if os.IsNotExist(err) {
				return Config{}, overlayPath, fmt.Errorf("environment overlay %q not found: %s", env, overlayPath)
			}
			return Config{}, overlayPath, fmt.Errorf("stat %s: %w", overlayPath, err)
		}
		if err := loadInto(&cfg, overlayPath); err != nil {
			return Config{}, overlayPath, err
		}
	}

	if cfg.ProjectName == "" {
		cfg.ProjectName = "resistack"
	}
	normalizeLegacy(&cfg)
	return cfg, overlayPath, nil
}

func ValidateEnvName(env string) error {
	env = strings.TrimSpace(env)
	if env == "" {
		return nil
	}
	if !envNamePattern.MatchString(env) {
		return fmt.Errorf("invalid environment %q: use lowercase letters, digits, '-' or '_'", env)
	}
	return nil
}

func overlayPathForEnv(path string, env string) string {
	ext := filepath.Ext(path)
	if ext == "" {
		return path + "." + env
	}
	base := strings.TrimSuffix(path, ext)
	return base + "." + env + ext
}

func loadInto(cfg *Config, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func (cfg Config) PrimaryDomain() string {
	if len(cfg.AppInventory.Domains) == 0 {
		return ""
	}
	return strings.TrimSpace(cfg.AppInventory.Domains[0])
}
