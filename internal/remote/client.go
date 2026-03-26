package remote

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"

	"github.com/hciupinski/resistancestack/internal/fsutil"
	"github.com/hciupinski/resistancestack/internal/scriptutil"
)

type Target struct {
	Host            string
	User            string
	Port            int
	KeyPath         string
	HostKeyChecking string
	KnownHostsPath  string
}

func (t Target) address() string {
	return t.User + "@" + t.Host
}

func (t Target) sshArgs() []string {
	args := []string{
		"-p", strconv.Itoa(t.Port),
		"-i", fsutil.ExpandHome(t.KeyPath),
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
	}

	switch strings.ToLower(strings.TrimSpace(t.HostKeyChecking)) {
	case "", "strict":
		args = append(args, "-o", "StrictHostKeyChecking=yes")
		if knownHostsPath := fsutil.ExpandHome(t.KnownHostsPath); knownHostsPath != "" {
			args = append(args, "-o", "UserKnownHostsFile="+knownHostsPath)
		}
	case "accept-new":
		args = append(args, "-o", "StrictHostKeyChecking=accept-new")
		if knownHostsPath := fsutil.ExpandHome(t.KnownHostsPath); knownHostsPath != "" {
			args = append(args, "-o", "UserKnownHostsFile="+knownHostsPath)
		}
	default:
		args = append(args, "-o", "StrictHostKeyChecking=yes")
	}

	return args
}

func Run(target Target, command string, stdout, stderr io.Writer) error {
	args := append(target.sshArgs(), target.address(), command)
	cmd := exec.Command("ssh", args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh run failed: %w", err)
	}
	return nil
}

func RunScript(target Target, script string, stdout, stderr io.Writer) error {
	args := append(target.sshArgs(), target.address(), "bash -s")
	cmd := exec.Command("ssh", args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = bytes.NewBufferString(script)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh script failed: %w", err)
	}
	return nil
}

func CaptureScript(target Target, script string) (string, error) {
	args := append(target.sshArgs(), target.address(), "bash -s")
	cmd := exec.Command("ssh", args...)
	cmd.Stdin = bytes.NewBufferString(script)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ssh capture script failed: %w (%s)", err, stderr.String())
	}
	return out.String(), nil
}

func Capture(target Target, command string) (string, error) {
	args := append(target.sshArgs(), target.address(), command)
	cmd := exec.Command("ssh", args...)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ssh capture failed: %w (%s)", err, stderr.String())
	}
	return out.String(), nil
}

func Upload(target Target, remotePath string, content []byte) error {
	command := fmt.Sprintf("cat > %s", scriptutil.ShellQuote(remotePath))
	args := append(target.sshArgs(), target.address(), command)
	cmd := exec.Command("ssh", args...)
	cmd.Stdin = bytes.NewReader(content)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh upload failed: %w (%s)", err, stderr.String())
	}
	return nil
}
