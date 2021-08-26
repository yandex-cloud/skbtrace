package main

import (
	"io"
	"os"

	"github.com/spf13/pflag"

	"github.com/yandex-cloud/skbtrace"
	"github.com/yandex-cloud/skbtrace/pkg/cli"
)

type Dependencies struct{}

func (d *Dependencies) AddFlags(flags *pflag.FlagSet) {}
func (d *Dependencies) Setup(ctx *cli.VisitorContext) {}
func (d *Dependencies) Output() io.Writer             { return os.Stdout }
func (d *Dependencies) ErrorOutput() io.Writer        { return os.Stderr }
func (d *Dependencies) Exit(code int)                 { os.Exit(code) }

func (d *Dependencies) PreprocessInterface(itfName string) (string, error) {
	return itfName, nil
}

func (d *Dependencies) GuessUnderlayDeviceFilters(itfName string) ([]*skbtrace.Filter, error) {
	return nil, nil
}

func main() {
	rootCmd := cli.RootCommand.NewRootCommand(&Dependencies{})
	rootCmd.Execute()
}
