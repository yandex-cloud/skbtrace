package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/yandex-cloud/skbtrace"
)

type TracerCommandVisitor interface {
	Visit(ctx *VisitorContext, cmd *cobra.Command, opts *skbtrace.TraceCommonOptions)
}

func (producer *CommandProducer) addTracer(
	ctx *VisitorContext, cmd *cobra.Command, commonOpts *skbtrace.CommonOptions,
) {
	var opts skbtrace.TraceCommonOptions
	PassCommonOptions(ctx, cmd, &opts.CommonOptions, commonOpts)
	RegisterTracerProbeOptions(cmd.Flags(), &opts)
	RegisterTracerContextOptions(cmd.Flags(), &opts)
	RegisterFilterOptions(cmd.Flags(), &opts.FilterOptions)
	RegisterInterfaceOptions(ctx, cmd, &opts.FilterOptions)

	producer.walkTracerTree(ctx, cmd, &opts)
}

func (producer *CommandProducer) walkTracerTree(
	ctx *VisitorContext, cmd *cobra.Command, opts *skbtrace.TraceCommonOptions,
) {
	producer.TracerVisitor.Visit(ctx, cmd, opts)

	for _, child := range producer.Children {
		childCmd := child.newCommand(cmd)
		if child.TracerVisitor == nil {
			panic(fmt.Sprintf("error tracer tree '%s': child '%s' is not a tracer",
				cmd.Name(), childCmd.Name()))
		}

		chain := ctx.Save()
		child.walkTracerTree(ctx, childCmd, opts)
		ctx.Restore(chain)

		cmd.AddCommand(childCmd)
	}
}

func PassTraceCommonOptions(
	ctx *VisitorContext, cmd *cobra.Command, dst, src *skbtrace.TraceCommonOptions,
) {
	ctx.AddPreRun(cmd, func(cmd *cobra.Command, args []string) error {
		*dst = *src
		return nil
	})
}

type DumpTracerCommand struct {
	Visitor func(ctx *VisitorContext, cmd *cobra.Command, opts *skbtrace.TraceDumpOptions)
}

func (dumper *DumpTracerCommand) Visit(
	ctx *VisitorContext, cmd *cobra.Command,
	commonOpts *skbtrace.TraceCommonOptions,
) {
	var opts skbtrace.TraceDumpOptions
	PassTraceCommonOptions(ctx, cmd, &opts.TraceCommonOptions, commonOpts)
	dumper.Visitor(ctx, cmd, &opts)

	cmd.Run = NewRun(ctx, func() (*skbtrace.Program, error) {
		return ctx.Builder.BuildDumpTrace(opts)
	})
}

var CommonDumpTracerCommand = &CommandProducer{
	Base: &cobra.Command{
		Use:     "dump -P PROBE...",
		Example: "dump -6 -P free -F 'dst == 2a02:6b8:...' -K -o ipv6",
		Short:   "Prints requested rows each time probe is fired",
	},
	TracerVisitor: &DumpTracerCommand{
		Visitor: func(ctx *VisitorContext, cmd *cobra.Command, opts *skbtrace.TraceDumpOptions) {
			RegisterCommonDumpOptions(cmd.Flags(), &opts.CommonDumpOptions)
		},
	},
}

type AggregateTracerCommand struct {
	Visitor func(ctx *VisitorContext, cmd *cobra.Command, opts *skbtrace.TraceAggregateOptions)
}

func (dumper *AggregateTracerCommand) Visit(
	ctx *VisitorContext, cmd *cobra.Command,
	commonOpts *skbtrace.TraceCommonOptions,
) {
	opts := skbtrace.TraceAggregateOptions{
		AggregateCommonOptions: skbtrace.AggregateCommonOptions{
			Interval: time.Second,
		},
		Func: skbtrace.AFCount,
	}
	PassTraceCommonOptions(ctx, cmd, &opts.TraceCommonOptions, commonOpts)
	dumper.Visitor(ctx, cmd, &opts)

	cmd.Run = NewRun(ctx, func() (*skbtrace.Program, error) {
		return ctx.Builder.BuildAggregate(opts)
	})
}

func RegisterAggregateOptions(flags *pflag.FlagSet, opts *skbtrace.TraceAggregateOptions) {
	flags.VarPF(&aggrFuncValue{&opts.Func}, "func", "f",
		"Aggregation function. All functions except count require a numeric argument.")
	flags.StringVarP(&opts.Arg, "arg", "a", "",
		"Field used as argument to aggregation function")
	flags.StringSliceVarP(&opts.Keys, "key", "k", nil,
		`Keys to merge probe firings. Use 'fields' subcommand to list available fields.`)
}

var CommonAggregateCommand = &CommandProducer{
	Base: &cobra.Command{
		Use:     "aggregate -P PROBE... -f FUNC [-a ARG] -k KEYS [INTERVAL]",
		Example: "aggregate -6 -P xmit -i eth1 -F 'inner-src == 2a02:6b8:...' -k outer-dst 2s",
		Short:   "Aggregates probe firings by specified set of keys",
		Aliases: []string{"aggr"},
		Args:    cobra.RangeArgs(0, 1),
	},

	TracerVisitor: &AggregateTracerCommand{
		Visitor: func(ctx *VisitorContext, cmd *cobra.Command, opts *skbtrace.TraceAggregateOptions) {
			flags := cmd.Flags()
			RegisterAggregateOptions(flags, opts)
			RegisterAggregateCommonOptions(flags, &opts.AggregateCommonOptions)
			RegisterTimeIntervalArg(ctx, cmd, &opts.Interval)
		},
	},
}
