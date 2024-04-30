package clitesting

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yandex-cloud/skbtrace"
	"github.com/yandex-cloud/skbtrace/pkg/cli"
)

const maxFileNameLen = 100

type testGroup struct {
	name string

	bpftraceVer string
	kernelVer   string
}

type (
	TestBPFVersionProvider struct {
		skbtrace.BPFTraceVersionProvider
	}
	TestKernelVersionProvider struct {
		skbtrace.KernelVersionProvider
	}
)

func (TestBPFVersionProvider) Get() ([]byte, error)    { panic("tests should use version argument") }
func (TestKernelVersionProvider) Get() ([]byte, error) { panic("tests should use version argument") }

type testDeps struct {
	output io.Writer
}

func (d *testDeps) AddFlags(flags *pflag.FlagSet) {}
func (d *testDeps) Setup(ctx *cli.VisitorContext) {}
func (d *testDeps) Output() io.Writer             { return d.output }
func (d *testDeps) ErrorOutput() io.Writer        { return d.output }
func (d *testDeps) Exit(code int)                 {}

func (d *testDeps) PreprocessInterface(itfName string) (string, error) {
	return itfName, nil
}

func (d *testDeps) GuessUnderlayDeviceFilters(itfName string) ([]*skbtrace.Filter, error) {
	return nil, nil
}

func (d *testDeps) FeatureComponents() map[string]skbtrace.FeatureComponentSpec {
	return map[string]skbtrace.FeatureComponentSpec{
		"bpftrace": {
			Component: skbtrace.FeatureComponentBPFTrace,
			Provider:  &TestBPFVersionProvider{},
		},
		"kernel": {
			Component: skbtrace.FeatureComponentKernel,
			Provider:  &TestKernelVersionProvider{},
		},
	}
}

func RunCommandTest(t *testing.T, args []string) {
	cmdlineStr := strings.Join(args, "_")
	errorMsg := fmt.Sprintf("Error in test for command %s", cmdlineStr)
	for _, punct := range []string{"/", ":", " ", ">", `"`} {
		cmdlineStr = strings.ReplaceAll(cmdlineStr, punct, "_")
	}

	for _, g := range []testGroup{
		{
			name:        "base",
			bpftraceVer: "bpftrace v0.9.0",
			kernelVer:   "4.14.0",
		},
		{
			name:        "current",
			bpftraceVer: "bpftrace v0.18.0",
			kernelVer:   "5.15.0",
		},
	} {
		testArgs := append([]string{
			"--dump",
			"--bpftrace-version=" + g.bpftraceVer,
			"--kernel-version=" + g.kernelVer,
		}, args...)

		t.Run(g.name+"/"+cmdlineStr, func(t *testing.T) {
			buf, err := executeCommand(testArgs)
			require.NoError(t, err, errorMsg)

			testOutputPath := fmt.Sprintf("testdata/%s/%s.txt", g.name, cmdlineStr)
			if _, err := os.Stat(testOutputPath); os.IsNotExist(err) {
				// On the first run (or if file was deleted) rewrite expected output
				os.WriteFile(testOutputPath, buf.Bytes(), 0644)
			} else {
				// If expected output is provided, compare results
				expected, _ := os.ReadFile(testOutputPath)
				expectedLines := strings.Split(string(expected), "\n")
				actualLines := strings.Split(buf.String(), "\n")
				assert.ElementsMatch(t, expectedLines, actualLines, errorMsg)
			}
		})
	}
}

func executeCommand(args []string) (output *bytes.Buffer, err error) {
	buf := bytes.NewBuffer(nil)
	rootCmd := cli.RootCommand.NewRootCommand(&testDeps{output: buf})

	rootCmd.SetArgs(args)
	_, err = rootCmd.ExecuteC()

	return buf, err
}
