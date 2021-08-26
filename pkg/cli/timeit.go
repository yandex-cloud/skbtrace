package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/yandex-cloud/skbtrace"
)

func (producer *CommandProducer) addTimeIt(
	ctx *VisitorContext, cmd *cobra.Command, commonOpts *skbtrace.CommonOptions,
) {
	var opts skbtrace.TimeCommonOptions
	ctx.AddPreRun(cmd, func(cmd *cobra.Command, args []string) error {
		opts.CommonOptions = *commonOpts
		return nil
	})

	producer.walkTimeItTree(ctx, cmd, &opts)
}

func (producer *CommandProducer) walkTimeItTree(
	ctx *VisitorContext, cmd *cobra.Command, opts *skbtrace.TimeCommonOptions,
) {
	producer.TimeVisitor(ctx, cmd, opts)
	for _, child := range producer.Children {
		childCmd := child.newCommand(cmd)
		if child.TimeVisitor == nil {
			panic(fmt.Sprintf("error tracer tree '%s': child '%s' is not a timeit",
				cmd.Name(), childCmd.Name()))
		}

		chain := ctx.Save()
		child.walkTimeItTree(ctx, childCmd, opts)
		ctx.Restore(chain)

		cmd.AddCommand(childCmd)
	}
}

func CommonTimeItVisitor(
	ctx *VisitorContext, cmd *cobra.Command, specPtr *skbtrace.TimeSpec,
) {
	RegisterFilterOptions(cmd.Flags(), &specPtr.FilterOptions)
	RegisterInterfaceOptions(ctx, cmd, &specPtr.FilterOptions)

	cmd.Flags().StringVarP(&specPtr.Probe, "probe", "P", "",
		`Probe name to use. Use 'probes' subcommand to list available probes.`)
	cmd.Flags().StringSliceVarP(&specPtr.Keys, "key", "k", nil,
		`Keys to merge probe firings. Use 'fields' subcommand to list available fields.`)
}

func PassTimeCommonOptions(ctx *VisitorContext, cmd *cobra.Command, dst, src *skbtrace.TimeCommonOptions) {
	ctx.AddPreRun(cmd, func(cmd *cobra.Command, args []string) error {
		*dst = *src
		return nil
	})
}

func NewDefaultAggregateRun(ctx *VisitorContext, commonOpts *skbtrace.TimeCommonOptions) CommandRunFunc {
	return NewRun(ctx, func() (*skbtrace.Program, error) {
		opts := skbtrace.TimeAggregateOptions{
			TimeCommonOptions: *commonOpts,
			Func:              skbtrace.AFHist,
			Interval:          time.Second,
		}
		return ctx.Builder.BuildTimeAggregate(opts)
	})
}

var CommonTimeItFromCommand = &CommandProducer{
	Base: &cobra.Command{
		Use:   "timeit",
		Short: "Measures time delta between two distinct events 'from' and 'to'",
	},
	TimeVisitor: func(ctx *VisitorContext, cmd *cobra.Command, opts *skbtrace.TimeCommonOptions) {

	},
	Children: []*CommandProducer{
		timeItFromCommand,
		ForwardCommand,
		BaseTcpCommand,
	},
}

var timeItFromCommand = &CommandProducer{
	Base: &cobra.Command{
		Use:   "from",
		Short: "Time measurement with explicitly specified probes",
	},
	TimeVisitor: func(ctx *VisitorContext, cmd *cobra.Command, opts *skbtrace.TimeCommonOptions) {
		CommonTimeItVisitor(ctx, cmd, &opts.FromSpec)
	},
	Children: []*CommandProducer{
		timeItToCommand,
	},
}

var timeItToCommand = &CommandProducer{
	Base: &cobra.Command{
		Use:   "to",
		Short: "Specification of probe that measures time delta after 'from' probe firing",
	},
	TimeVisitor: func(ctx *VisitorContext, cmd *cobra.Command, opts *skbtrace.TimeCommonOptions) {
		CommonTimeItVisitor(ctx, cmd, &opts.ToSpec)
		cmd.Run = NewDefaultAggregateRun(ctx, opts)
	},
	Children: DefaultTimeSubcommands,
}

var DefaultTimeSubcommands = []*CommandProducer{
	TimeAggregateCommand,
	TimeOutlierDumpSubcommand,
	TimeEventCountSubcommand,
}

var TimeAggregateCommand = &CommandProducer{
	Base: &cobra.Command{
		Use:     "aggregate [-f FUNC] [INTERVAL]",
		Aliases: []string{"aggr"},
		Short:   "Aggregates time delta using specified function",
		Args:    cobra.RangeArgs(0, 1),
	},
	TimeVisitor: func(ctx *VisitorContext, cmd *cobra.Command, commonOpts *skbtrace.TimeCommonOptions) {
		opts := skbtrace.TimeAggregateOptions{
			Func:     skbtrace.AFHist,
			Interval: time.Second,
		}
		RegisterTimeIntervalArg(ctx, cmd, &opts.Interval)
		PassTimeCommonOptions(ctx, cmd, &opts.TimeCommonOptions, commonOpts)

		cmd.Run = NewRun(ctx, func() (*skbtrace.Program, error) {
			return ctx.Builder.BuildTimeAggregate(opts)
		})
	},
}

var TimeOutlierDumpSubcommand = &CommandProducer{
	Base: &cobra.Command{
		Use:   "outliers -t THRESHOLD",
		Short: "Dumps structures that exceed specified threshold",
	},
	TimeVisitor: func(ctx *VisitorContext, cmd *cobra.Command, commonOpts *skbtrace.TimeCommonOptions) {
		var opts skbtrace.TimeOutlierDumpOptions
		PassTimeCommonOptions(ctx, cmd, &opts.TimeCommonOptions, commonOpts)

		flags := cmd.Flags()
		RegisterCommonDumpOptions(flags, &opts.CommonDumpOptions)
		flags.DurationVarP(&opts.OutlierThreshold, "threshold", "t",
			100*time.Millisecond,
			"Threshold for time delta. If hit, probe firing is considered an outlier.")
		flags.BoolVar(&opts.Exit, "exit", false,
			"Exit after dumping first outlier.")

		cmd.Run = NewRun(ctx, func() (*skbtrace.Program, error) {
			return ctx.Builder.BuildTimeOutlierDump(opts)
		})
	},
}

var TimeEventCountSubcommand = &CommandProducer{
	Base: &cobra.Command{
		Use:   "evcount",
		Short: "Counts each time from or to probe is hit. Useful for testing filters.",
	},
	TimeVisitor: func(ctx *VisitorContext, cmd *cobra.Command, commonOpts *skbtrace.TimeCommonOptions) {
		cmd.Run = NewRun(ctx, func() (*skbtrace.Program, error) {
			return ctx.Builder.BuildTimeEventCount(*commonOpts)
		})
	},
}

var CommonDuplicateCommand = &CommandProducer{
	Base: &cobra.Command{
		Use:     "duplicate",
		Short:   "Dumps objects when hit twice with the same set of keys",
		Aliases: []string{"dup"},
	},
	CommonVisitor: func(ctx *VisitorContext, cmd *cobra.Command, commonOpts *skbtrace.CommonOptions) {
		var opts skbtrace.DuplicateEventOptions
		PassCommonOptions(ctx, cmd, &opts.CommonOptions, commonOpts)

		flags := cmd.Flags()
		RegisterCommonDumpOptions(flags, &opts.CommonDumpOptions)
		flags.BoolVar(&opts.Exit, "exit", false,
			"exit after dumping first outlier.")

		cmd.Run = NewRun(ctx, func() (*skbtrace.Program, error) {
			return ctx.Builder.BuildDuplicateEvent(opts)
		})
	},
}
