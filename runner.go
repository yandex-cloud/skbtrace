package skbtrace

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var bpfTraceEnv = []string{
	// Required to handle IPv6 addresses
	"BPFTRACE_STRLEN=80",
}

type RunnerOptions struct {
	DumpScript     bool
	BPFTraceBinary string
}

type BPFTraceVersionProvider struct{}

// NOTE: Yandex Cloud internal builds use build version prefix
var (
	reBPFTraceVersion = regexp.MustCompile(`bpftrace (?:v|gv|build-)(\d+)\.(\d+)\.(\d+)`)
	reBPFTraceBuild   = regexp.MustCompile(`-(\d+)\.(\d+)`)
)
var safeDefaultVersion = Version{Major: 0, Submajor: 9, Minor: 2}

func (BPFTraceVersionProvider) Get() ([]byte, error) {
	cmd := exec.Command("bpftrace", "-V")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error running bpftrace: %w", err)
	}
	return out, nil
}

func (BPFTraceVersionProvider) Parse(out []byte) (Version, error) {
	matches := reBPFTraceVersion.FindSubmatch(out)
	if len(matches) < 4 {
		return safeDefaultVersion, fmt.Errorf("unexpected number of matches in bpftrace version %q", out)
	}

	verNumbers := matches[1:]
	tail := out[len(matches[0]):]
	tailMatches := reBPFTraceBuild.FindSubmatch(tail)
	if len(tailMatches) > 1 {
		verNumbers = append(verNumbers, tailMatches[1:]...)
	}

	return NewVersionFromMatches(verNumbers)
}

func (BPFTraceVersionProvider) GetDefault() Version {
	return safeDefaultVersion
}

func Run(w io.Writer, prog *Program, opt RunnerOptions) error {
	if opt.DumpScript {
		fmt.Fprintf(w, "sudo %s %s -e '\n", strings.Join(bpfTraceEnv, " "), opt.BPFTraceBinary)
		prog.render(w, true)
		fmt.Fprintln(w, "'")
		return nil
	}

	f, err := ioutil.TempFile(os.TempDir(), "skbtrace")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())

	err = prog.render(f, false)
	if err != nil {
		return err
	}

	cmd := exec.Command("sudo", "--preserve-env", opt.BPFTraceBinary, f.Name())
	cmd.Stdout = w
	cmd.Stderr = w
	cmd.Env = append(cmd.Env, bpfTraceEnv...)
	return cmd.Run()
}
