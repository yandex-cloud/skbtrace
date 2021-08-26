package skbtrace

import (
	"regexp"
	"strings"
)

const (
	// Comparison operators in filters. Same as in bpftrace
	reFilterOpGroup = "(==|!=|>=|<=|<|>)"

	// Filter value. Supports dotted notation and some string constants
	// for field preprocessors
	reFilterValueGroup = "([A-Za-z0-9.:|]*)"
)

var reFilter = regexp.MustCompile("^" + strings.Join(
	[]string{reFieldObjGroup, reFieldFieldGroups,
		reFilterOpGroup, reFilterValueGroup}, "\\s*") + "$")

type Filter struct {
	Object string
	Field  string
	Op     string
	Value  string
}

type FilterOptions struct {
	RawFilters []string
	Filters    []*Filter
}

type ProcessedFilter struct {
	Filter

	fref *fieldAliasRef
}

type weakAliasFieldRef struct {
	filter *ProcessedFilter
}

func (f *Filter) fieldIdent() string {
	return string(ExprField(f.Object, f.Field))
}

func (f *Filter) withField(fref *fieldAliasRef) *ProcessedFilter {
	newFilter := &ProcessedFilter{Filter: *f}
	if fref.fg != nil {
		newFilter.Object = fref.fg.Object
	}
	newFilter.Field = fref.field.Name
	newFilter.fref = fref
	return newFilter
}

func (b *Builder) prepareFilters(opt FilterOptions) ([][]*ProcessedFilter, error) {
	filters := make([][]*ProcessedFilter, 0, len(opt.RawFilters)+len(opt.Filters))

	for _, filter := range opt.Filters {
		filterChunk, err := b.processFilter(filter)
		if err != nil {
			return nil, err
		}

		filters = append(filters, filterChunk)
	}

	for _, rawFilter := range opt.RawFilters {
		filterChunk, err := b.parseFilter(rawFilter)
		if err != nil {
			return nil, err
		}

		filters = append(filters, filterChunk)
	}

	return filters, nil
}

func (b *Builder) parseFilter(rawFilter string) ([]*ProcessedFilter, error) {
	groups := reFilter.FindStringSubmatch(rawFilter)
	if len(groups) < 4 || len(groups) > 5 {
		return nil, newCommonError(ErrLevelFilter, rawFilter, ErrMsgParseError)
	}

	fieldName := groups[1]
	if len(groups) == 5 {
		fieldName = groups[2]
	}

	filter := &Filter{
		Object: groups[1],
		Field:  fieldName,
		Op:     groups[len(groups)-2],
		Value:  groups[len(groups)-1],
	}
	return b.processFilter(filter)
}

func (b *Builder) processFilter(filter *Filter) ([]*ProcessedFilter, error) {
	fref := b.findField(filter.Object, filter.Field)
	if fref == nil {
		return nil, newErrorf(ErrLevelFilter, filter.fieldIdent(), nil,
			"not found field used by filter")
	}

	pf := filter.withField(fref)
	return []*ProcessedFilter{pf}, nil
}

func (b *Builder) processFieldSanityFilters(obj string) []*ProcessedFilter {
	var sanityFilters []*ProcessedFilter
	fields := b.fieldObjectMap[obj]
	for _, fref := range fields {
		if fref.field.SanityFilter == nil {
			continue
		}
		sanityFilters = append(sanityFilters, fref.field.SanityFilter.withField(fref))
	}

	return sanityFilters
}

// Add adds if block with filters
func (b *Builder) addFilterBlock(
	block *Block, filters []*ProcessedFilter,
) (*Block, error) {
	if len(filters) == 0 {
		return block, nil
	}

	var conditions []Expression
	for _, filter := range filters {
		fref, field := filter.fref, filter.fref.field
		filterStmts, expr, err := b.generateFieldExpression(fref.fg, field, block.probe, ConverterFilter)
		if err != nil {
			return nil, newErrorf(ErrLevelFilter, filter.fieldIdent(), err,
				"error generating field expression in filter")
		}

		block.Add(filterStmts...)

		var condExprList []Expression
		for _, value := range strings.Split(filter.Value, "|") {
			if filter.fref.field.Preprocessor != nil {
				// Preprocess human-readable value
				preprocessedValue, err := filter.fref.field.Preprocessor(filter.Op, filter.Value)
				if err != nil {
					return nil, newErrorf(ErrLevelFilter, filter.fieldIdent(), err,
						"error preprocessing value")
				}
				value = preprocessedValue
			}

			var condExpr Expression
			if field.FilterOperator != nil {
				condExpr, err = field.FilterOperator(expr, filter.Op, value)
				if err != nil {
					return nil, newErrorf(ErrLevelFilter, filter.fieldIdent(), err,
						"error in filter operator")
				}
			} else {
				condExpr = Exprf("%s %s %s", expr, filter.Op, value)
			}
			condExprList = append(condExprList, condExpr)
		}
		conditions = append(conditions, ExprJoinOp(condExprList, "||"))
	}

	return block.AddIfBlock(conditions...), nil
}

func (b *Builder) getFilterWeakRefs(filters [][]*ProcessedFilter) []weakAliasRef {
	weakRefs := make([]weakAliasRef, 0)
	for _, filterChunk := range filters {
		for _, filter := range filterChunk {
			if filter.fref.weakGroups != nil {
				weakRefs = append(weakRefs, &weakAliasFieldRef{filter})
			}
		}
	}
	return weakRefs
}

func (w *weakAliasFieldRef) Ref() *fieldAliasRef {
	return w.filter.fref
}

func (w *weakAliasFieldRef) Level() ErrorLevel {
	return ErrLevelFilter
}

func (w *weakAliasFieldRef) Resolve(fg *FieldGroup) {
	w.filter.fref.Resolve(fg)
	w.filter.Object = fg.Object
}
