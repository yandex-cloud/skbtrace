package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/yandex-cloud/skbtrace"
	"github.com/yandex-cloud/skbtrace/pkg/skb"
	"github.com/yandex-cloud/skbtrace/pkg/stringutil"
)

type forwardOptions struct {
	filterOptions   skbtrace.FilterOptions
	itfNames        []string
	underlayItfName string
	isIngress       bool
	isEgress        bool
}

var (
	forwardKeysRaw = []string{"src", "dst", "id"}
	forwardKeysUdp = []string{"src", "dst", "sport", "dport"}
	forwardKeysTcp = []string{"src", "dst", "sport", "dport", "seq"}

	forwardUsageError = errors.New("exactly two interfaces or" +
		" one interface with ingress/egress flag is expected")
)

var ForwardCommand = &CommandProducer{
	Base: &cobra.Command{
		Use:     "forward {{--ingress|--egress} -i ITF|-i INITF -i OUTITF} [OPTIONS]",
		Example: "forward --ingress -i tapxx-0 -6",
		Short:   "Measures time spent forwarding a packet from ingress interface to egress interface",
	},
	TimeVisitor: func(ctx *VisitorContext, cmd *cobra.Command, opts *skbtrace.TimeCommonOptions) {
		var fwdOpts forwardOptions
		registerForwardOptions(cmd.PersistentFlags(), &fwdOpts)

		ctx.AddPreRun(cmd, func(cmd *cobra.Command, args []string) error {
			err := handleForwardFiltersInterface(ctx, &opts.FromSpec, skb.ProbeRecv,
				&opts.CommonOptions, &fwdOpts)
			if err != nil {
				return err
			}
			return handleForwardFiltersInterface(ctx, &opts.ToSpec, skb.ProbeXmit,
				&opts.CommonOptions, &fwdOpts)
		})

		cmd.Run = NewDefaultAggregateRun(ctx, opts)
	},
	Children: DefaultTimeSubcommands,
}

func handleForwardFiltersInterface(
	ctx *VisitorContext, spec *skbtrace.TimeSpec, probe string,
	commonOpts *skbtrace.CommonOptions, fwdOpts *forwardOptions,
) (err error) {
	wrapError := func(err error) error {
		return fmt.Errorf("error in forward interface probe %s: %v", probe, err)
	}

	var encapOpt bool
	var itfFilter []*skbtrace.Filter

	if fwdOpts.isIngress || fwdOpts.isEgress {
		// -i ITF1 --ingress - ingress to a VM
		// -i ITF1 --egress  - egress from a VM
		if len(fwdOpts.itfNames) != 1 {
			return wrapError(forwardUsageError)
		}

		itfName := fwdOpts.itfNames[0]
		if fwdOpts.isIngress {
			switch probe {
			case skb.ProbeRecv:
				itfFilter, err = buildUnderlayFilter(ctx, itfName, fwdOpts.underlayItfName)
				encapOpt = true
			case skb.ProbeXmit:
				itfFilter, err = buildInterfaceFilter(ctx, itfName)
			}
		} else if fwdOpts.isEgress {
			switch probe {
			case skb.ProbeRecv:
				itfFilter, err = buildInterfaceFilter(ctx, itfName)
			case skb.ProbeXmit:
				itfFilter, err = buildUnderlayFilter(ctx, itfName, fwdOpts.underlayItfName)
				encapOpt = true
			}
		}
	} else {
		// -i ITF1 -i ITF2 - raw forwarding within a machine
		if len(fwdOpts.itfNames) != 2 {
			return wrapError(forwardUsageError)
		}

		switch probe {
		case skb.ProbeRecv:
			itfFilter, err = buildInterfaceFilter(ctx, fwdOpts.itfNames[0])
		case skb.ProbeXmit:
			itfFilter, err = buildInterfaceFilter(ctx, fwdOpts.itfNames[1])
		}
	}
	if err != nil {
		return wrapError(err)
	}

	spec.Probe = probe
	spec.Keys, spec.Hints = buildForwardKeys(encapOpt, commonOpts)
	spec.FilterOptions = skbtrace.FilterOptions{
		RawFilters: fwdOpts.filterOptions.RawFilters,
		Filters:    append(fwdOpts.filterOptions.Filters, itfFilter...),
	}
	return nil
}

func buildForwardKeys(encapOpt bool, commonOpts *skbtrace.CommonOptions) (keys []string, hints []string) {
	if stringutil.SliceContains(commonOpts.Hints, "tcp") {
		keys = forwardKeysTcp
		if encapOpt {
			hints = []string{"inner-tcp"}
		}
	} else if stringutil.SliceContains(commonOpts.Hints, "udp") {
		keys = forwardKeysUdp
		if encapOpt {
			hints = []string{"inner-udp"}
		}
	} else {
		keys = forwardKeysRaw
	}

	if encapOpt {
		keys = wrapEncap(keys)
	}
	return
}

func registerDirectionFlags(flags *pflag.FlagSet, ingressPtr, egressPtr *bool) {
	flags.BoolVar(ingressPtr, "ingress", false,
		"Direction is ingress (towards specified interface)")
	flags.BoolVar(egressPtr, "egress", false,
		"Direction is egress (from specified interface)")
}

func registerForwardOptions(flags *pflag.FlagSet, opts *forwardOptions) {
	flags.StringSliceVarP(&opts.itfNames, "iface", "i", []string{},
		`Interface device name. Can be specified twice with second being`+
			` egress interface in local forwarding.`)
	flags.StringVarP(&opts.underlayItfName, "underlay-iface", "u", defaultUnderlayDevice,
		`Default underlay device used if it cannot be guessed`)
	registerDirectionFlags(flags, &opts.isIngress, &opts.isEgress)
	RegisterFilterOptions(flags, &opts.filterOptions)
}
