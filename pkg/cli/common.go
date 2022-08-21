package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/yandex-cloud/skbtrace"
	"github.com/yandex-cloud/skbtrace/pkg/skb"
)

const (
	defaultUnderlayDevice = "eth1"
	defaultContextKey     = "tid"
)

// rawFilterSlice is a variant of stringSlice from cobra that doesn't use
// CSV internally. This allows for CSV-incompatible arguments
type rawFilterSlice struct {
	value *[]string
}

func newRawFilterSliceValue(p *[]string) *rawFilterSlice {
	rfsv := new(rawFilterSlice)
	rfsv.value = p
	return rfsv
}

func (rfsv *rawFilterSlice) Type() string { return "RawFilters" }
func (rfsv *rawFilterSlice) String() string {
	return strings.Join(*rfsv.value, " && ")
}
func (rfsv *rawFilterSlice) Set(s string) error {
	rawFilters := strings.Split(s, "&&")
	for _, rawFilter := range rawFilters {
		*rfsv.value = append(*rfsv.value, strings.TrimSpace(rawFilter))
	}
	return nil
}

type timeModeValue struct {
	tm *skbtrace.TimeMode
}

func (v *timeModeValue) Type() string   { return "TimeMode" }
func (v *timeModeValue) String() string { return string(*v.tm) }
func (v *timeModeValue) Set(newValue string) error {
	*v.tm = skbtrace.TimeMode(newValue)
	return nil
}

type aggrFuncValue struct {
	af *skbtrace.AggrFunc
}

func (v *aggrFuncValue) Type() string   { return "AggrFunc" }
func (v *aggrFuncValue) String() string { return string(*v.af) }
func (v *aggrFuncValue) Set(newValue string) error {
	for _, afValue := range skbtrace.AggrFuncList {
		if string(afValue) == newValue {
			*v.af = afValue
			return nil
		}
	}

	return fmt.Errorf("invalid aggregate function '%s'", newValue)
}

func PassCommonOptions(ctx *VisitorContext, cmd *cobra.Command, dst, src *skbtrace.CommonOptions) {
	ctx.AddPreRun(cmd, func(cmd *cobra.Command, args []string) error {
		*dst = *src
		return nil
	})
}

func NewDeviceFilter(itfName string) *skbtrace.Filter {
	return &skbtrace.Filter{
		Object: skb.DevNameAlias, Op: "==",
		Value: fmt.Sprintf(`"%s"`, itfName)}
}

func RegisterCommonDumpOptions(flags *pflag.FlagSet, opt *skbtrace.CommonDumpOptions) {
	opt.TimeMode = skbtrace.TMTime

	flags.VarPF(&timeModeValue{&opt.TimeMode}, "time-mode", "",
		`Time mode: 'time' for absolute wall time clock,`+
			` 'delta' for elapsed time from previous probe firing`+
			` or 'nsecs'/'elapsed' raw bpftrace global variables.`)
	flags.StringSliceVarP(&opt.FieldGroupRows, "row", "o", nil,
		`Rows to be dumped. Use 'rows' helper to show available rows.`)
	flags.BoolVarP(&opt.KStack, "kstack", "K", false,
		`Dump kernel stack on each probe.`)
	flags.BoolVarP(&opt.UStack, "ustack", "U", false,
		`Dump userspace stack on each probe.`)
}

func RegisterFilterOptions(flags *pflag.FlagSet, options *skbtrace.FilterOptions) {
	flags.VarP(newRawFilterSliceValue(&options.RawFilters), "filter", "F",
		`Filters. Use 'fields' subcommand to list available fields.`)
}

func RegisterTracerProbeOptions(flags *pflag.FlagSet, opts *skbtrace.TraceCommonOptions) {
	flags.StringSliceVarP(&opts.ProbeNames, "probe", "P", nil,
		`Probe names to generate. Use 'probes' subcommand to list available probes.`)
}

func RegisterTracerContextOptions(flags *pflag.FlagSet, opts *skbtrace.TraceCommonOptions) {
	flags.StringSliceVarP(&opts.ContextProbeNames, "context-probe", "C", nil,
		`Probe names that trigger normal probe execution. Use 'probes' subcommand to list available probes.`)
	flags.Var(newRawFilterSliceValue(&opts.ContextFilterOptions.RawFilters), "context-filter",
		`Filters. Use 'fields' subcommand to list available fields.`)
	flags.StringVar(&opts.ContextKey, "context-key", defaultContextKey,
		`Key to be used to map context probe firings to normal probe firings`)
}

func RegisterInterfaceOptions(
	ctx *VisitorContext, cmd *cobra.Command, options *skbtrace.FilterOptions,
) {
	var itfName string
	cmd.PersistentFlags().StringVarP(&itfName, "iface", "i", "",
		`Interface device name. Shortcut for '$netdev->name == "Device"' filter.`)

	ctx.AddPreRun(cmd, func(cmd *cobra.Command, args []string) error {
		if itfName == "" {
			return nil
		}

		itfName, err := ctx.Dependencies.PreprocessInterface(itfName)
		if err != nil {
			return err
		}

		options.Filters = append(options.Filters, NewDeviceFilter(itfName))
		return nil
	})
}

func RegisterTimeIntervalArg(ctx *VisitorContext, cmd *cobra.Command, interval *time.Duration) {
	ctx.AddPreRun(cmd, func(cmd *cobra.Command, args []string) (err error) {
		if len(args) == 1 {
			*interval, err = time.ParseDuration(args[0])
		}
		return
	})
}

func buildInterfaceFilter(ctx *VisitorContext, itfName string) ([]*skbtrace.Filter, error) {
	itfName, err := ctx.Dependencies.PreprocessInterface(itfName)
	if err == nil {
		return []*skbtrace.Filter{NewDeviceFilter(itfName)}, nil
	}
	return nil, err
}

func buildUnderlayFilter(ctx *VisitorContext, itfName, underlayName string) ([]*skbtrace.Filter, error) {
	underlayFilter, err := ctx.Dependencies.GuessUnderlayDeviceFilters(itfName)
	if underlayFilter == nil && err == nil {
		underlayFilter = []*skbtrace.Filter{NewDeviceFilter(underlayName)}
	}
	return underlayFilter, err
}

func wrapEncap(origKeys []string) []string {
	keys := make([]string, len(origKeys))
	for i := range origKeys {
		keys[i] = "inner-" + origKeys[i]
	}
	return keys
}
