package skbtrace

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var bpfTraceEnv = []string{
	// Required to handle IPv6 addresses
	"BPFTRACE_STRLEN=80",
}

type Version struct {
	Major int
	Minor int
	Build int
}

type RunnerOptions struct {
	DumpScript     bool
	BPFTraceBinary string
}

var reBpfTraceVersion = regexp.MustCompile(`bpftrace v(\d+)\.(\d+)\.(\d+)`)
var safeDefaultVersion = Version{0, 9, 2}
var StructKeywordVersion = Version{0, 9, 4}

func (v Version) EqualOrNewer(v2 Version) bool {
	if v.Major != v2.Major {
		return v.Major > v2.Major
	}
	if v.Minor != v2.Minor {
		return v.Minor > v2.Minor
	}
	return v.Build > v2.Build
}

func GetVersion() Version {
	cmd := exec.Command("bpftrace", "-V")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return safeDefaultVersion
	}

	matches := reBpfTraceVersion.FindSubmatch(out)
	if len(matches) != 4 {
		return safeDefaultVersion
	}

	var ver Version
	for i, ptr := range []*int{&ver.Minor, &ver.Minor, &ver.Build} {
		*ptr, _ = strconv.Atoi(string(matches[i+1]))
	}
	return ver
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
