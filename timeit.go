package skbtrace

import (
	"errors"
	"fmt"
	"time"
)

const (
	aggrCleanupInterval = 5 * time.Second
)

const (
	TUSecond      = "sec"
	TUMillisecond = "ms"
	TUMicrosecond = "us"
	TUNanosecond  = "ns"
)

var timeUnitDivisors = map[string]time.Duration{
	TUSecond:      time.Second,
	TUMillisecond: time.Millisecond,
	TUMicrosecond: time.Microsecond,
	TUNanosecond:  1,
}

type TimeSpec struct {
	// Name of the probe this probe is refers to
	Probe string

	// Lists of filters applied to this probe
	FilterOptions

	// List of keys used to map requests
	Keys []string

	// Hints for this probe
	Hints []string
}

// TimeCommonOptions are shared between time options requests.
type TimeCommonOptions struct {
	CommonOptions

	// Specification of the probe in which start time is collected.
	FromSpec TimeSpec

	// Specification of the probe in which time delta is computed.
	// If filters or keys are omitted in ToSpec, they are derived from FromSpec.
	ToSpec TimeSpec
}

// Options for BuildTimeAggregate.
type TimeAggregateOptions struct {
	TimeCommonOptions

	// Aggregate Func for time and divisor for adjusting from nanoseconds
	Func AggrFunc

	// Interval is a interval between dumping common aggregation
	Interval time.Duration

	// ToEventCount is a number of to probe firings before we start
	// measuring time delta. Useful for measuring longer handshakes
	// such as TLS handshake for each 2nd ACK is of interest
	ToEventCount int
}

// Options for BuildTimeOutlierDump.
type TimeOutlierDumpOptions struct {
	TimeCommonOptions

	// OutlierThreshold allows to dump events which time exceed specified threshold
	OutlierThreshold time.Duration

	// Specifies if exit() should be called on first outlier
	Exit bool

	CommonDumpOptions
}

// Options for BuildDuplicateEvent.
type DuplicateEventOptions struct {
	CommonOptions

	// Specification of the probe
	Spec TimeSpec

	// Specifies if exit() should be called on first duplicate
	Exit bool

	CommonDumpOptions
}

// timeBuilderHelper is a function which injects statements into a probe
// block (and sometimes replaces it with nested block). Combining these
// functions allows to flexible build all options that timeit provides.
type timeBuilderHelper func(b *Builder, ctx *timeProbeContext) error

type timeProbeContext struct {
	filters    [][]*ProcessedFilter
	probeName  string
	probeBlock *Block
	outerBlock *Block
	block      *Block
	keys       []*fieldAliasRef

	// For sharing between builder helpers
	keysExprs []Expression
}

func combineTimeHelpers(helpers ...timeBuilderHelper) timeBuilderHelper {
	return func(b *Builder, ctx *timeProbeContext) error {
		for _, helper := range helpers {
			err := helper(b, ctx)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

func newTimeMeasurePrepare(convMask uint) timeBuilderHelper {
	return func(b *Builder, ctx *timeProbeContext) error {
		keyBlock, exprs, err := b.getBlockWithKeys(ctx.block, ctx.keys, convMask)
		if err != nil {
			return err
		}

		ctx.block = keyBlock
		ctx.keysExprs = exprs
		return nil
	}
}

func timeMeasureStartImpl(b *Builder, ctx *timeProbeContext) error {
	ctx.block.Addf("@start_time[%s] = nsecs", ExprJoin(ctx.keysExprs))
	return nil
}

func newTimeMeasureStart(convMask uint) timeBuilderHelper {
	return combineTimeHelpers(newTimeMeasurePrepare(convMask), timeMeasureStartImpl)
}

func timeMeasureStartFetchImpl(b *Builder, ctx *timeProbeContext) error {
	ctx.block.Addf("$st = @start_time[%s]", ExprJoin(ctx.keysExprs))
	ctx.block = ctx.block.AddIfBlock(Expr("$st > 0"))
	return nil
}

func timeMeasureDeltaImpl(b *Builder, ctx *timeProbeContext) error {
	ctx.block.Add(Stmt("$dt = (nsecs - $st)"))
	return nil
}

func newTimeMeasureDelta(convMask uint) timeBuilderHelper {
	return combineTimeHelpers(newTimeMeasurePrepare(convMask), timeMeasureStartFetchImpl, timeMeasureDeltaImpl)
}

func getTimeUnitDivisor(timeUnit string) (int64, error) {
	divisor, ok := timeUnitDivisors[timeUnit]
	if !ok {
		return 0, fmt.Errorf("unknown divisor '%s'", timeUnit)
	}
	return int64(divisor), nil
}

func newEventCounter(toEventCount int) timeBuilderHelper {
	return func(b *Builder, ctx *timeProbeContext) error {
		if toEventCount >= 2 {
			ctx.block.Addf("@event_count[%s] += 1", ExprJoin(ctx.keysExprs))
			ctx.block = ctx.block.AddIfBlock(Exprf("@event_count[%s] >= %d",
				ExprJoin(ctx.keysExprs), toEventCount))
			ctx.block.Addf("delete(@event_count[%s])", ExprJoin(ctx.keysExprs))
		}
		return nil
	}
}

func newAggregateTimeDelta(aggrFunc AggrFunc, timeUnit string) timeBuilderHelper {
	return func(b *Builder, ctx *timeProbeContext) error {
		divisor, err := getTimeUnitDivisor(timeUnit)
		if err != nil {
			return err
		}

		ctx.block.Addf("@ = %s($dt / %d)", aggrFunc, divisor)
		return nil
	}
}

func newOutlierCondition(threshold time.Duration) timeBuilderHelper {
	return func(b *Builder, ctx *timeProbeContext) error {
		ctx.block = ctx.block.AddIfBlock(Exprf("$dt > %d", threshold.Nanoseconds()))
		return nil
	}
}

func newDumper(opt *CommonOptions, dumpOpt CommonDumpOptions, exit bool) timeBuilderHelper {
	return func(b *Builder, ctx *timeProbeContext) error {
		divisor, err := getTimeUnitDivisor(opt.TimeUnit)
		if err != nil {
			return err
		}

		ctx.block.Addf(`printf("TIME: %%d %s\n", $dt / %d)`, opt.TimeUnit, divisor)

		err = b.addDumpRowsStatements(ctx.block, dumpOpt)
		if err != nil {
			return err
		}

		if exit {
			ctx.block.Add(Stmt("exit()"))
		}
		return nil
	}
}

func newEventCount(event string) timeBuilderHelper {
	return func(b *Builder, ctx *timeProbeContext) error {
		ctx.block.Addf(`@["%s:filtered"] = count()`, event)
		ctx.probeBlock.Addf(`@["%s"] = count()`, event)
		return nil
	}
}

func newDuplicateEvent() timeBuilderHelper {
	return func(b *Builder, ctx *timeProbeContext) error {
		ctx.block.Addf("$st = @start_time[%s]", ExprJoin(ctx.keysExprs))

		outerBlock := ctx.block
		ctx.block = ctx.block.AddIfBlock(Expr("$st == 0"))
		timeMeasureStartImpl(b, ctx)

		ctx.block = outerBlock.AddBlock("else")
		ctx.block.Add(Stmt(`printf("DUPLICATE EVENT ")`))
		return timeMeasureDeltaImpl(b, ctx)
	}
}

func newAggrCleanup(aggrVar string) timeBuilderHelper {
	return func(b *Builder, ctx *timeProbeContext) error {
		if len(ctx.keysExprs) == 0 {
			return errors.New("internal error: aggregate cleanup called before time measurement")
		}

		ctx.block.Addf("delete(%s[%s])", aggrVar, ExprJoin(ctx.keysExprs))
		return nil
	}
}

// BuildTimeAggregate is a default time mode builder: meaures time deltas, puts them
// into aggregation and periodically dumps aggregation contents.
func (b *Builder) BuildTimeAggregate(opt TimeAggregateOptions) (*Program, error) {
	prog, err := b.buildTimeTrace(
		&opt.TimeCommonOptions, nil,
		newTimeMeasureStart(ConverterHiddenKey),
		combineTimeHelpers(
			newEventCounter(opt.ToEventCount),
			newTimeMeasureDelta(ConverterHiddenKey),
			newAggregateTimeDelta(opt.Func, opt.TimeUnit),
			newAggrCleanup("@start_time")))
	if err != nil {
		return nil, err
	}

	aggrs := []string{"@start_time"}
	if opt.ToEventCount >= 2 {
		aggrs = append(aggrs, "@event_count")
	}

	prog.addAggrDumpBlock(opt.Interval)
	prog.addAggrCleanupBlock(aggrs...)
	return prog, err
}

// BuildTimeOutlierDump builds trace script which mearures time delta,
// but instead of putting it into an aggregation, it dumps objects that
// reveal such behaviour, i.e. tcp packet which causes troublingly long handshake.
func (b *Builder) BuildTimeOutlierDump(opt TimeOutlierDumpOptions) (*Program, error) {
	prog, err := b.buildTimeTrace(
		&opt.TimeCommonOptions, opt.FieldGroupRows,
		newTimeMeasureStart(ConverterHiddenKey),
		combineTimeHelpers(
			newTimeMeasureDelta(ConverterHiddenKey),
			newOutlierCondition(opt.OutlierThreshold),
			newDumper(&opt.CommonOptions, opt.CommonDumpOptions, opt.Exit)))
	if err != nil {
		return nil, err
	}

	prog.addAggrCleanupBlock("@start_time")
	return prog, err
}

// BuildTimeEventCount builds a program which counts number of times from and to
// probes are hit. Useful when other time probes do not reveal anything useful
// because filter is incorrect.
func (b *Builder) BuildTimeEventCount(opt TimeCommonOptions) (*Program, error) {
	return b.buildTimeTrace(
		&opt, nil,
		newEventCount("from"),
		newEventCount("to"))
}

// BuildDuplicateEvent builds a program which attaches to a single probe, but
// fires only when the probe hits same set of keys second time. Useful for
// tracking retransmits or measure port reuse time.
func (b *Builder) BuildDuplicateEvent(opt DuplicateEventOptions) (*Program, error) {
	prog := NewProgram()
	builder := combineTimeHelpers(
		newTimeMeasurePrepare(ConverterHiddenKey),
		newDuplicateEvent(),
		newDumper(&opt.CommonOptions, opt.CommonDumpOptions, opt.Exit))

	_, err := b.buildTimeProbe(prog, nil,
		opt.Spec, opt.FieldGroupRows, &opt.CommonOptions, builder)
	if err != nil {
		return nil, newProbeBuildError(opt.Spec.Probe, err)
	}

	prog.addAggrCleanupBlock("@start_time")
	return prog, err
}

func (b *Builder) buildTimeTrace(
	opt *TimeCommonOptions, rows []string,
	fromBuilder timeBuilderHelper,
	toBuilder timeBuilderHelper,
) (*Program, error) {
	prog := NewProgram()
	prog.addCommonBlock(&opt.CommonOptions)

	fromCtx, err := b.buildTimeProbe(prog, nil,
		opt.FromSpec, rows, &opt.CommonOptions, fromBuilder)
	if err != nil {
		return nil, newProbeBuildError(fmt.Sprintf("%s (from)", opt.FromSpec.Probe), err)
	}

	_, err = b.buildTimeProbe(prog, fromCtx,
		opt.ToSpec, rows, &opt.CommonOptions, toBuilder)
	if err != nil {
		return nil, newProbeBuildError(fmt.Sprintf("%s (to)", opt.ToSpec.Probe), err)
	}

	return prog, nil
}

func (b *Builder) buildTimeProbe(
	prog *Program, ctxBase *timeProbeContext,
	spec TimeSpec, rows []string, opt *CommonOptions,
	builder timeBuilderHelper,
) (ctx *timeProbeContext, err error) {
	// Build time probe. For "from probe" we build it initially meaning
	// that all values must be computed from scratch. For "to" probe we
	// can reuse probe, keys and filters if they are the same as in "from".
	ctx = &timeProbeContext{probeName: spec.Probe}
	if ctxBase == nil {
		ctxBase = &timeProbeContext{}
	}

	var boSet builderObjectSet
	getBoSet := func() builderObjectSet {
		if boSet == nil {
			boSet = b.newBuildObjectSet(ctx.filters, rows, append(opt.Hints, spec.Hints...))
		}
		return boSet
	}

	var sharedFilters bool
	if len(spec.Filters) > 0 || len(spec.RawFilters) > 0 {
		ctx.filters, err = b.prepareFilters(spec.FilterOptions)
		if err != nil {
			return
		}

		err = b.resolveWeakAliasRefs(b.getFilterWeakRefs(ctx.filters), getBoSet())
		if err != nil {
			return
		}
	} else {
		ctx.filters = ctxBase.filters
		sharedFilters = true
	}

	if spec.Probe != ctxBase.probeName || ctxBase.probeBlock == nil {
		ctx.probeBlock, ctx.outerBlock, err = b.addProbeBlock(prog, spec.Probe, false, ctx.filters)
	} else {
		ctx.probeBlock = ctxBase.probeBlock
		if !sharedFilters {
			ctx.outerBlock, err = b.wrapFilters(ctx.probeBlock, ctx.filters)
		} else {
			// Both filter and probe name are matching meaning that we can
			// reuse outer block from the previous probe
			ctx.outerBlock = ctxBase.outerBlock
		}
	}
	if err != nil {
		return
	}
	ctx.block = ctx.outerBlock

	if len(spec.Keys) > 0 {
		ctx.keys, err = b.prepareKeys(spec.Keys)
		if err != nil {
			return
		}

		err = b.resolveWeakAliasRefs(b.getFieldWeakRefs(ctx.keys), getBoSet())
		if err != nil {
			return
		}
	} else if ctxBase.keys != nil {
		ctx.keys = ctxBase.keys
	} else {
		err = errors.New("no keys supplied for time probe")
		return
	}

	err = builder(b, ctx)
	return
}
