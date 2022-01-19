package clitesting

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
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

func RunCommandTest(t *testing.T, args []string) {
	cmdlineStr := strings.Join(args, "_")
	errorMsg := fmt.Sprintf("Error in test for command %s", cmdlineStr)
	for _, punct := range []string{"/", ":", " ", ">"} {
		cmdlineStr = strings.ReplaceAll(cmdlineStr, punct, "_")
	}

	args = append([]string{"--dump", "--struct-keyword", ""}, args...)

	t.Run(cmdlineStr, func(t *testing.T) {
		buf, err := executeCommand(args)
		require.NoError(t, err, errorMsg)

		testOutputPath := "testdata/" + strings.Replace(cmdlineStr, "/", "_", -1) + ".txt"
		if _, err := os.Stat(testOutputPath); os.IsNotExist(err) {
			// On the first run (or if file was deleted) rewrite expected output
			ioutil.WriteFile(testOutputPath, buf.Bytes(), 0644)
		} else {
			// If expected output is provided, compare results
			expected, _ := ioutil.ReadFile(testOutputPath)
			expectedLines := strings.Split(string(expected), "\n")
			actualLines := strings.Split(buf.String(), "\n")
			assert.ElementsMatch(t, expectedLines, actualLines, errorMsg)
		}
	})

}

func executeCommand(args []string) (output *bytes.Buffer, err error) {
	buf := bytes.NewBuffer(nil)
	rootCmd := cli.RootCommand.NewRootCommand(&testDeps{output: buf})

	rootCmd.SetArgs(args)
	_, err = rootCmd.ExecuteC()

	return buf, err
}
