package skbtrace

import (
	"fmt"
	"time"
)

type TimeMode string

const (
	TMElapsed TimeMode = "elapsed"
	TMNSecs   TimeMode = "nsecs"
	TMDelta   TimeMode = "delta"
	TMTime    TimeMode = "time"
)

// CommonOptions are shared between tracer and time requests
type CommonOptions struct {
	Timeout time.Duration

	// Hints contains list of row names that are used for resolving weak aliases
	Hints []string

	// Time Unit for measuring times
	TimeUnit string
}

type TraceCommonOptions struct {
	CommonOptions

	ContextProbeNames    []string
	ContextFilterOptions FilterOptions
	ContextKey           string

	ProbeNames []string
	FilterOptions
}

type CommonDumpOptions struct {
	FieldGroupRows []string

	// Extra printer parameters
	TimeMode TimeMode
	KStack   bool
	UStack   bool
}

// Options for BuildDumpTrace
type TraceDumpOptions struct {
	TraceCommonOptions

	CommonDumpOptions
}

// Options for BuildAggregate
type TraceAggregateOptions struct {
	TraceCommonOptions

	// Aggregation Func and its argument (optional)
	Func AggrFunc
	Arg  string

	// Keys for aggregation map entry. Optionally, probe name may be added
	Keys []string

	// Interval of aggregation map dumping
	Interval time.Duration
}

func (b *Builder) buildTracerImpl(
	opt *TraceCommonOptions, rows []string,
	builder func(block *Block) error,
) (*Program, error) {
	filters, err := b.prepareFilters(opt.FilterOptions)
	if err != nil {
		return nil, err
	}

	boSet := b.newBuildObjectSet(filters, rows, opt.Hints)
	err = b.resolveWeakAliasRefs(b.getFilterWeakRefs(filters), boSet)
	if err != nil {
		return nil, err
	}

	prog := NewProgram()
	prog.addCommonBlock(&opt.CommonOptions)

	if len(opt.ContextProbeNames) > 0 {
		traceFlagExpr := Exprf("@trace_flag[%s]", opt.ContextKey)
		innerBuilder := builder
		builder = func(block *Block) error {
			innerBlock := block.AddIfBlock(traceFlagExpr)
			return innerBuilder(innerBlock)
		}

		contextFilters, err := b.prepareFilters(opt.ContextFilterOptions)
		if err != nil {
			return nil, err
		}

		for _, probeName := range opt.ContextProbeNames {
			if err = b.buildTracerProbe(prog, probeName, false, contextFilters, true, func(block *Block) error {
				block.Addf("%s = 1", traceFlagExpr)
				return nil
			}); err != nil {
				return nil, err
			}

			if err = b.buildTracerProbe(prog, probeName, true, nil, false, func(block *Block) error {
				block.Addf("delete(%s)", traceFlagExpr)
				return nil
			}); err != nil {
				return nil, err
			}
		}
	}

	for _, probeName := range opt.ProbeNames {
		if err = b.buildTracerProbe(prog, probeName, false, filters, true, builder); err != nil {
			return nil, err
		}
	}

	return prog, nil
}

func (b *Builder) buildTracerProbe(
	prog *Program, probeName string, isReturn bool, filters [][]*ProcessedFilter,
	countHits bool, builder func(block *Block) error,
) error {
	probeBlock, block, err := b.addProbeBlock(prog, probeName, isReturn, filters)
	if err != nil {
		return err
	}

	err = builder(block)
	if err != nil {
		return newProbeBuildError(probeName, err)
	}

	// Add diagnostic of number of times the probe was hit.
	// Will be printed on exit like any other global array
	if countHits {
		block.Addf(`@hits["%s:filtered"] = count()`, probeName)
		probeBlock.Addf(`@hits["%s"] = count()`, probeName)
	}
	return nil
}

// BuildDumpTrace builds a tracer where each probe prints known fields
// along with timestamp (as defined by time mode) if conditions specified
// by filters are met.
func (b *Builder) BuildDumpTrace(opt TraceDumpOptions) (*Program, error) {
	return b.buildTracerImpl(&opt.TraceCommonOptions, opt.FieldGroupRows,
		func(block *Block) error {
			return b.addDumpRowsStatements(block, opt.CommonDumpOptions)
		})
}

func (b *Builder) BuildAggregate(opt TraceAggregateOptions) (*Program, error) {
	prog, err := b.buildTracerImpl(&opt.TraceCommonOptions, []string{},
		func(block *Block) error {
			aggrBlock, aggrExpr, err := b.generateAggregateExpr(block, opt.Func, opt.Arg)
			if err != nil {
				return err
			}

			frefList, err := b.prepareKeys(opt.Keys)
			if err != nil {
				return err
			}

			// Use converters here as we're going to dump map with its keys
			keyBlock, keyExprs, err := b.getBlockWithKeys(aggrBlock, frefList, ConverterDump)
			if err != nil {
				return err
			}

			if len(opt.ProbeNames) > 1 {
				keyExprs = append(keyExprs, Exprf(`"%s"`, block.probe.Name))
			}
			if len(keyExprs) == 0 {
				keyBlock.Addf("@ = %s", aggrExpr)
			} else {
				keyBlock.Addf("@[%s] = %s", ExprJoin(keyExprs), aggrExpr)
			}
			return nil
		})
	if err != nil {
		return nil, err
	}

	prog.addAggrDumpBlock(opt.Interval)
	return prog, nil
}

func (b *Builder) wrapFilters(
	baseBlock *Block, filters [][]*ProcessedFilter,
) (block *Block, err error) {
	if len(filters) == 0 {
		return baseBlock, nil
	}

	block = baseBlock
	for _, filterChunk := range filters {
		block, err = b.wrapFilter(block, filterChunk)
		if err != nil {
			return nil, err
		}
	}
	return
}

func (b *Builder) wrapFilter(
	block *Block, filterChunk []*ProcessedFilter,
) (*Block, error) {
	// The only case for multiple filters are arrays, so assume
	// that both filters use same object
	block, err := b.getBlockWithObject(block, filterChunk[0].frefs[0].fg.Object)
	if err != nil {
		return nil, err
	}

	return b.addFilterBlock(block, filterChunk)
}

func (b *Builder) addDumpRowsStatements(block *Block, opt CommonDumpOptions) (err error) {
	if len(opt.FieldGroupRows) == 0 {
		return newCommonError(ErrLevelProbe, block.probe.Name, "no rows are specified in dump options")
	}

	for rowIndex, row := range opt.FieldGroupRows {
		fgList, ok := b.fieldGroupMap[row]
		if !ok {
			return newCommonError(ErrLevelRow, row, ErrMsgNotFound)
		}

		objBlock := block
		for fgIndex, fg := range fgList {
			if _, ok := block.context[fg.Object]; !ok {
				objBlock, err = b.getBlockWithObject(block, fg.Object)
				if err != nil {
					return err
				}
			}

			// Defer all printing until we pass sanity filters
			if rowIndex == 0 && fgIndex == 0 {
				err := b.addTimeStatements(objBlock, opt.TimeMode, block.probe.Name)
				if err != nil {
					return err
				}
			}

			stmts, err := b.generatePrintStatements(fg, block.probe)
			if err != nil {
				return err
			}
			objBlock.Add(stmts...)
		}

		if rowIndex == len(opt.FieldGroupRows)-1 {
			if opt.KStack {
				b.addStackStatement(objBlock, "kstack")
			}
			if opt.UStack {
				b.addStackStatement(objBlock, "ustack")
			}
		}
	}

	return nil
}

func (b *Builder) addStackStatement(block *Block, stkVar string) {
	block.Addf(`printf("%%s\n", %s)`, stkVar)
}

func (b *Builder) addTimeStatements(block *Block, timeMode TimeMode, probeName string) error {
	expr, fmtSpec, preStmts, postStmts, err := b.getTimeStatements(timeMode)
	if err != nil {
		return err
	}

	block.Add(preStmts...)
	block.Addf(`printf("%s - %s\n", %s)`, fmtSpec, probeName, expr)
	block.Add(postStmts...)
	return nil
}

func (b *Builder) getTimeStatements(timeMode TimeMode) (
	expr Expression, fmtSpec string,
	pre []Statement, post []Statement,
	err error,
) {
	switch timeMode {
	case TMDelta:
		expr = "elapsed - @last_event"
		post = []Statement{Stmtf("@last_event = elapsed")}
		fmtSpec = "+%ld"
	case TMTime:
		pre = []Statement{Stmt(`time("%H:%M:%S.")`)}
		expr = "nsecs % 1000000000"
		fmtSpec = "%09ld"
	case TMNSecs, TMElapsed:
		expr = Expression(timeMode)
		fmtSpec = " %ld"
	default:
		err = fmt.Errorf("unknown time mode '%s'", timeMode)
	}

	return
}

func (b *Builder) generateAggregateExpr(
	block *Block, aggrFunc AggrFunc, arg string,
) (*Block, Expression, error) {
	switch aggrFunc {
	case AFCount:
		return block, Expr("count()"), nil
	}

	var argExprs []Expression
	frefList, err := b.prepareKeys([]string{arg})
	if err != nil {
		return nil, NilExpr, err
	}

	block, argExprs, err = b.getBlockWithKeys(block, frefList, ConverterAggregateArg)
	if err != nil {
		return block, NilExpr, err
	}

	aggrExpr := Exprf("%s(%s)", aggrFunc, ExprJoin(argExprs))
	return block, aggrExpr, nil
}
