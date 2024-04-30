package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/yandex-cloud/skbtrace"
	"github.com/yandex-cloud/skbtrace/pkg/proto"
	"github.com/yandex-cloud/skbtrace/pkg/skb"
)

const (
	defaultTimeout = time.Minute
)

type PreRunEFunc func(cmd *cobra.Command, args []string) error
type PreRunEChain []PreRunEFunc

// CommandProducer workarounds cobra limitations, specifically:
//   - lack of ability to inject parsed data structures (and tending to
//     use global structures)
//   - "persistent" methods are being inherited, but overridden, wherever
//     skbtrace requires a combination of both.
//
// To avoid that, each node in CommandProducer tree implements one of
// the *Visitor methods which receives:
//   - current visitor context including some global options
//   - command to register options, pre-run and run methods
//   - pointer to most-specific set of options (not filled yet,
//     as parsing is done on command execution).
//
// Each Visitor method might produce even more specific options structure
// and link another pre-run function that will copy options parsed by
// prior commands to it or even create unique options structure such as
// tcpOptions and process into raw TimeCommonOptions in pre-run.
// Note that all options processing is done in pre-run (so after argument
// parsing).
//
// Finally, leaf CommandProducers register cmd.Run in their visitors
// adding real implementation to the command supplied.
type CommandProducer struct {
	Base     *cobra.Command
	Children []*CommandProducer

	InfoVisitor   func(ctx *VisitorContext, cmd *cobra.Command)
	CommonVisitor func(ctx *VisitorContext, cmd *cobra.Command, opts *skbtrace.CommonOptions)
	TracerVisitor TracerCommandVisitor
	TimeVisitor   func(ctx *VisitorContext, cmd *cobra.Command, opts *skbtrace.TimeCommonOptions)
}

type Dependencies interface {
	AddFlags(flags *pflag.FlagSet)
	Setup(ctx *VisitorContext)

	// Returns output for runner interface
	Output() io.Writer
	ErrorOutput() io.Writer

	// Exits command line in case of error
	Exit(code int)

	// PreprocessInterface preprocesses interface name specified by -i
	// to support alternative spellings such as container name automatically
	// converted to the linux device name
	PreprocessInterface(itfName string) (string, error)

	// GuessUnderlayDeviceFilters guesses which filters should be applied to
	// probe specification which are suitable for the interface, for example
	// multiple underlay interfaces with differing labels might exist
	GuessUnderlayDeviceFilters(itfName string) ([]*skbtrace.Filter, error)

	// FeatureComponents provides a map of supported feature component specifications
	FeatureComponents() map[string]skbtrace.FeatureComponentSpec
}

type VisitorContext struct {
	Builder      *skbtrace.Builder
	Dependencies Dependencies

	RunnerOptions skbtrace.RunnerOptions

	IsIPv6    bool
	EncapType string

	featureMaskArgs  [skbtrace.FeatureComponentCount]string
	featureVerArgs   [skbtrace.FeatureComponentCount]string
	FeatureFlagMasks [skbtrace.FeatureComponentCount]skbtrace.FeatureFlagMask

	PreRunEChain PreRunEChain
}

func (base *CommandProducer) newCommand(parent *cobra.Command) *cobra.Command {
	if base.Base == nil {
		return parent
	}

	cmd := *base.Base
	cmd.TraverseChildren = true
	if parent != nil {
		cmd.PreRunE = parent.PreRunE
	}
	return &cmd
}

// NewRootCommand creates a root command with all of its children
// rendered into cobra.Command structures.
func (root *CommandProducer) NewRootCommand(deps Dependencies) *cobra.Command {
	var opts skbtrace.CommonOptions
	ctx := &VisitorContext{
		Builder:      skbtrace.NewBuilder(),
		Dependencies: deps,
		RunnerOptions: skbtrace.RunnerOptions{
			BPFTraceBinary: "bpftrace",
		},
	}

	rootCmd := root.newCommand(nil)
	root.registerRootFlags(rootCmd.PersistentFlags(), ctx, &opts)
	deps.AddFlags(rootCmd.PersistentFlags())

	rootCmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		err := root.setup(ctx, &opts)
		if err != nil {
			return err
		}

		deps.Setup(ctx)
		return nil
	}
	ctx.PreRunEChain = append(ctx.PreRunEChain, rootCmd.PreRunE)

	cobra.EnableCommandSorting = false
	for _, child := range root.Children {
		childCmd := child.newCommand(rootCmd)
		child.commonVisit(ctx, childCmd, &opts)
		rootCmd.AddCommand(childCmd)
	}

	addHiddenCommands(rootCmd)
	return rootCmd
}

func (root *CommandProducer) registerRootFlags(
	flags *pflag.FlagSet, ctx *VisitorContext, opts *skbtrace.CommonOptions,
) {
	flags.BoolVarP(&ctx.RunnerOptions.DumpScript, "dump", "D", false,
		`Dump bpftrace command instead of running it`)
	flags.StringVar(&ctx.RunnerOptions.BPFTraceBinary, "bpftrace", "bpftrace",
		`Path to bpftrace binary`)
	flags.DurationVarP(&opts.Timeout, "timeout", "T", defaultTimeout,
		`Execution timeout for resulting bpftrace script`)
	flags.StringVarP(&ctx.EncapType, "encap", "e", proto.EncapProtoUdp,
		`Type of encapsulation: 'gre' or 'udp'`)
	flags.BoolVarP(&ctx.IsIPv6, "inet6", "6", false,
		`If specified, skbtrace assumes that inner header is IPv6.`)
	flags.StringSliceVarP(&opts.Hints, "hint", "p", nil,
		`Protocol hints for weak field aliases such as 'tcp' for 'sport'.`)
	flags.StringVar(&opts.TimeUnit, "unit", skbtrace.TUMicrosecond,
		`Time unit using for measurements: 'sec', 'ms', 'us' - default or 'ns'`)

	for name, spec := range ctx.Dependencies.FeatureComponents() {
		flags.StringVar(&ctx.featureVerArgs[spec.Component], fmt.Sprintf("%s-version", name), "",
			fmt.Sprintf(`Specifies %s version compatibility level`, name))
		flags.StringVar(&ctx.featureMaskArgs[spec.Component], fmt.Sprintf("%s-features", name), "",
			fmt.Sprintf(`Specifies %s features as comma separated list`, name))
	}
}

func (root *CommandProducer) setup(ctx *VisitorContext, opts *skbtrace.CommonOptions) error {
	for name, spec := range ctx.Dependencies.FeatureComponents() {
		mask, err := spec.ProcessFeatures(ctx.featureVerArgs[spec.Component], ctx.featureMaskArgs[spec.Component])
		if err != nil {
			return fmt.Errorf("error processing features of component %q: %w", name, err)
		}
		ctx.FeatureFlagMasks[spec.Component] = mask
	}

	var (
		bpfTraceFeatureMask = ctx.FeatureFlagMasks[skbtrace.FeatureComponentBPFTrace]
		kernelFeatureMask   = ctx.FeatureFlagMasks[skbtrace.FeatureComponentKernel]
	)
	ctx.Builder.SetFeatures(bpfTraceFeatureMask)

	skb.RegisterSkb(ctx.Builder, bpfTraceFeatureMask, kernelFeatureMask)
	skb.RegisterTask(ctx.Builder)

	proto.RegisterEth(ctx.Builder, bpfTraceFeatureMask)
	proto.RegisterEncap(ctx.Builder, ctx.EncapType, bpfTraceFeatureMask)
	proto.RegisterIp(ctx.Builder, ctx.IsIPv6, bpfTraceFeatureMask)
	proto.RegisterTransport(ctx.Builder, ctx.IsIPv6, bpfTraceFeatureMask)

	proto.RegisterOverlayLengthFunc(ctx.Builder, ctx.EncapType)
	proto.RegisterInnerIpLengthFunc(ctx.Builder, ctx.IsIPv6)

	if ctx.IsIPv6 {
		opts.Hints = append(opts.Hints, "ipv6", "inner-ipv6")
	}
	return nil
}

func (producer *CommandProducer) commonVisit(
	ctx *VisitorContext, cmd *cobra.Command, commonOpts *skbtrace.CommonOptions,
) {
	chain := ctx.Save()
	defer ctx.Restore(chain)

	if producer.InfoVisitor != nil {
		producer.InfoVisitor(ctx, cmd)
	} else if producer.CommonVisitor != nil {
		producer.walkCommonTree(ctx, cmd, commonOpts)
	} else if producer.TracerVisitor != nil {
		producer.addTracer(ctx, cmd, commonOpts)
	} else if producer.TimeVisitor != nil {
		producer.addTimeIt(ctx, cmd, commonOpts)
	} else {
		panic(fmt.Sprintf("unexpected Visit() on producer '%s' without visitors", cmd.Name()))
	}
}

func (producer *CommandProducer) walkCommonTree(
	ctx *VisitorContext, cmd *cobra.Command, opts *skbtrace.CommonOptions,
) {
	producer.CommonVisitor(ctx, cmd, opts)

	for _, child := range producer.Children {
		childCmd := child.newCommand(cmd)

		chain := ctx.Save()
		child.commonVisit(ctx, childCmd, opts)
		ctx.Restore(chain)

		cmd.AddCommand(childCmd)
	}
}

func (ctx *VisitorContext) Save() PreRunEChain {
	return ctx.PreRunEChain
}

func (ctx *VisitorContext) Restore(chain PreRunEChain) {
	ctx.PreRunEChain = chain
}

func (ctx *VisitorContext) AddPreRun(cmd *cobra.Command, impl PreRunEFunc) {
	ctx.PreRunEChain = append(ctx.PreRunEChain, impl)

	chain := ctx.PreRunEChain
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		for _, cb := range chain {
			err := cb(cmd, args)
			if err != nil {
				return err
			}
		}
		return nil
	}
}
