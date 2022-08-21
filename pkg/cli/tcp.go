package cli

import (
	"errors"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/yandex-cloud/skbtrace"
	"github.com/yandex-cloud/skbtrace/pkg/skb"
)

type tcpOptions struct {
	filterOpts skbtrace.FilterOptions
	direction  directionOptions
	isUnderlay bool
}

var (
	tcpKeysBase            = []string{"sport", "dport"}
	tcpExtraKeysRetransmit = []string{"seq", "ack", "iplen"}
)

var BaseTcpCommand = &CommandProducer{
	Base: &cobra.Command{
		Use:   "tcp",
		Short: "Measures tcp-related timings and outliers",
	},
	TimeVisitor: func(ctx *VisitorContext, cmd *cobra.Command, commonOpts *skbtrace.TimeCommonOptions) {
		var opts tcpOptions
		RegisterInterfaceOptions(ctx, cmd, &opts.filterOpts)
		registerTcpOptions(cmd.PersistentFlags(), &opts)

		ctx.AddPreRun(cmd, func(cmd *cobra.Command, args []string) error {
			return buildTcpTimeOptions(&opts, commonOpts)
		})
	},
	Children: []*CommandProducer{
		TcpHandshakeCommand,
		TcpLifetimeCommand,
		TcpRetransmitsCommand,
	},
}

var TcpHandshakeCommand = &CommandProducer{
	Base: &cobra.Command{
		Use:     "handshake {--inbound|--outbound} [--underlay] -i ITF",
		Example: "handshake --inbound -i tapxx-0 -6",
		Short:   "Measures time for TCP handshake",
	},
	TimeVisitor: func(ctx *VisitorContext, cmd *cobra.Command, opts *skbtrace.TimeCommonOptions) {
		ctx.AddPreRun(cmd, func(cmd *cobra.Command, args []string) error {
			opts.FromSpec.RawFilters = append(opts.FromSpec.RawFilters, "tcp-flags == S")
			opts.ToSpec.RawFilters = append(opts.ToSpec.RawFilters, "tcp-flags == A")
			return nil
		})
		cmd.Run = NewDefaultAggregateRun(ctx, opts)
	},
	Children: DefaultTimeSubcommands,
}

var TcpLifetimeCommand = &CommandProducer{
	Base: &cobra.Command{
		Use:   "lifetime {--inbound|--outbound}",
		Short: "Measures TCP connection lifetime from SYN to FIN/RST in the same direction",
	},
	TimeVisitor: func(ctx *VisitorContext, cmd *cobra.Command, opts *skbtrace.TimeCommonOptions) {
		ctx.AddPreRun(cmd, func(cmd *cobra.Command, args []string) error {
			opts.FromSpec.RawFilters = append(opts.FromSpec.RawFilters, "tcp-flags == S")
			opts.ToSpec.RawFilters = append(opts.ToSpec.RawFilters, "tcp-flags == F|FA|R")
			return nil
		})

		cmd.Run = NewDefaultAggregateRun(ctx, opts)
	},
	Children: DefaultTimeSubcommands,
}

var TcpRetransmitsCommand = &CommandProducer{
	Base: &cobra.Command{
		Use:   "retransmit",
		Short: "Detects duplicate packets",
	},
	TimeVisitor: func(ctx *VisitorContext, cmd *cobra.Command, commonOpts *skbtrace.TimeCommonOptions) {
		var opts skbtrace.DuplicateEventOptions
		RegisterCommonDumpOptions(cmd.Flags(), &opts.CommonDumpOptions)

		ctx.AddPreRun(cmd, func(cmd *cobra.Command, args []string) error {
			opts.CommonOptions = commonOpts.CommonOptions
			opts.Spec = commonOpts.FromSpec
			opts.Spec.Keys = append(tcpKeysBase, tcpExtraKeysRetransmit...)
			return nil
		})

		cmd.Run = NewRun(ctx, func() (*skbtrace.Program, error) {
			return ctx.Builder.BuildDuplicateEvent(opts)
		})
	},
}

func buildTcpTimeOptions(opts *tcpOptions, commonOpts *skbtrace.TimeCommonOptions) error {
	var probeName string
	keys := append(newIpForwardKeys(opts.direction), tcpKeysBase...)
	hints := []string{"tcp"}
	if opts.isUnderlay {
		if opts.direction.isInbound {
			probeName = skb.ProbeRecv
		} else if opts.direction.isOutbound {
			probeName = skb.ProbeXmit
		}
		keys = wrapEncap(keys)
		hints = wrapEncap(hints)
	} else {
		if opts.direction.isInbound {
			probeName = skb.ProbeXmit
		} else if opts.direction.isOutbound {
			probeName = skb.ProbeRecv
		}
	}
	if probeName == "" {
		return errors.New("either --inbound or --outbound flag should be specified")
	}

	commonOpts.FromSpec = skbtrace.TimeSpec{
		Probe:         probeName,
		FilterOptions: opts.filterOpts,
		Keys:          keys,
		Hints:         hints,
	}
	commonOpts.ToSpec = skbtrace.TimeSpec{
		Probe:         probeName,
		FilterOptions: opts.filterOpts,
		Keys:          keys,
		Hints:         hints,
	}
	return nil
}

func registerTcpOptions(flags *pflag.FlagSet, opts *tcpOptions) {
	RegisterFilterOptions(flags, &opts.filterOpts)
	flags.BoolVar(&opts.isUnderlay, "underlay", false,
		"Capture TCP in underlay interface.")
	registerDirectionFlags(flags, &opts.direction)
}
