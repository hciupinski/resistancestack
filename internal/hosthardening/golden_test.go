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
	want := "bbf01cbec3aaa5bfd708ac98fe50a109085ea3cac592d3f2aeb9c0e152b3d836"
	if got != want {
		t.Fatalf("unexpected apply script hash %s", got)
	}
}

func TestBuildRollbackScript_DefaultHash(t *testing.T) {
	cfg := config.Default("demo")
	got := fmt.Sprintf("%x", sha256.Sum256([]byte(BuildRollbackScript(cfg))))
	want := "2ca03d9e0e37f838b8bc9982a54d838fff932a943d9d6a9114cf921b3e9ad0fe"
	if got != want {
		t.Fatalf("unexpected rollback script hash %s", got)
	}
}
