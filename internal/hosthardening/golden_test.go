package hosthardening

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/hciupinski/resistancestack/internal/config"
)

func TestBuildApplyScript_DefaultHash(t *testing.T) {
	cfg := config.Default("demo")
	got := fmt.Sprintf("%x", sha256.Sum256([]byte(BuildApplyScript(cfg))))
	want := "31e1d6c4295509edb2fe326ddd9675090538c4999f97bb67fafa37cbecfa4483"
	if got != want {
		t.Fatalf("unexpected apply script hash %s", got)
	}
}

func TestBuildRollbackScript_DefaultHash(t *testing.T) {
	cfg := config.Default("demo")
	got := fmt.Sprintf("%x", sha256.Sum256([]byte(BuildRollbackScript(cfg))))
	want := "ad4609582e65f212920c6bf9e3e2f6c40e2e0c674a5040f73d5c6aab9317a467"
	if got != want {
		t.Fatalf("unexpected rollback script hash %s", got)
	}
}
