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
	want := "17728834efa3618872841843ad143704594621fdee61226d23da87caa4683468"
	if got != want {
		t.Fatalf("unexpected apply script hash %s", got)
	}
}

func TestBuildRollbackScript_DefaultHash(t *testing.T) {
	cfg := config.Default("demo")
	got := fmt.Sprintf("%x", sha256.Sum256([]byte(BuildRollbackScript(cfg))))
	want := "fece57c290d74b0e4c09bf27e42cda39d609393cc5d1df80d3bb367026a38365"
	if got != want {
		t.Fatalf("unexpected rollback script hash %s", got)
	}
}
