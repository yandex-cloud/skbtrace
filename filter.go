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
	reFilterValueGroup = "([\"]?[A-Za-z0-9.:|]*[\"]?)"
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

	frefs []*fieldAliasRef
}

type weakAliasFieldRef struct {
	filter *ProcessedFilter
}

func (f *Filter) fieldIdent() string {
	return string(ExprField(f.Object, f.Field))
}

func (f *Filter) withFields(frefs []*fieldAliasRef) *ProcessedFilter {
	newFilter := &ProcessedFilter{Filter: *f}
	if frefs[0].fg != nil {
		newFilter.Object = frefs[0].fg.Object
	}

	var fieldNames []string
	for _, fref := range frefs {
		fieldNames = append(fieldNames, fref.field.Name)
	}
	newFilter.Field = strings.Join(fieldNames, "|")

	newFilter.frefs = frefs
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
	objects := strings.Split(filter.Object, "|")
	fields := strings.Split(filter.Field, "|")

	var frefs []*fieldAliasRef
	for _, obj := range objects {
		for _, field := range fields {
			fref := b.findField(obj, field)
			if fref == nil {
				return nil, newErrorf(ErrLevelFilter, filter.fieldIdent(), nil,
					"not found field used by filter")
			}

			frefs = append(frefs, fref)
		}
	}

	baseFref := frefs[0]
	for _, fref := range frefs[1:] {
		if baseFref.fg != fref.fg {
			return nil, newErrorf(ErrLevelFilter, filter.fieldIdent(), nil,
				"cannot use field refs from different objects '%s' and '%s'",
				baseFref.fg.Object, fref.fg.Object)
		}
	}

	pf := filter.withFields(frefs)
	return []*ProcessedFilter{pf}, nil
}

func (b *Builder) processFieldSanityFilters(obj string) []*ProcessedFilter {
	var sanityFilters []*ProcessedFilter
	fields := b.fieldObjectMap[obj]
	for _, fref := range fields {
		if fref.field.SanityFilter == nil {
			continue
		}
		sanityFilters = append(sanityFilters,
			fref.field.SanityFilter.withFields([]*fieldAliasRef{fref}))
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
		var exprs []Expression
		for _, fref := range filter.frefs {
			stmts, expr, err := b.generateFieldExpression(fref.fg, fref.field, block.probe, ConverterFilter)
			if err != nil {
				return nil, newErrorf(ErrLevelFilter, filter.fieldIdent(), err,
					"error generating field expression in filter")
			}

			block.Add(stmts...)
			exprs = append(exprs, expr)
		}

		var condExprList []Expression
		for _, value := range strings.Split(filter.Value, "|") {
			for i, fref := range filter.frefs {
				fieldValue := value
				if fref.field.Preprocessor != nil {
					// Preprocess human-readable value
					preprocessedValue, err := fref.field.Preprocessor(filter.Op, value)
					if err != nil {
						return nil, newErrorf(ErrLevelFilter, filter.fieldIdent(), err,
							"error preprocessing value")
					}
					fieldValue = preprocessedValue
				}

				if fref.field.FilterOperator != nil {
					condExpr, err := fref.field.FilterOperator(exprs[i], filter.Op, fieldValue)
					if err != nil {
						return nil, newErrorf(ErrLevelFilter, filter.fieldIdent(), err,
							"error in filter operator")
					}
					condExprList = append(condExprList, condExpr)
				} else {
					condExprList = append(condExprList,
						Exprf("%s %s %s", exprs[i], filter.Op, fieldValue))
				}
			}
		}
		conditions = append(conditions, ExprJoinOp(condExprList, "||"))
	}

	return block.AddIfBlock(conditions...), nil
}

func (b *Builder) getFilterWeakRefs(filters [][]*ProcessedFilter) []weakAliasRef {
	weakRefs := make([]weakAliasRef, 0)
	for _, filterChunk := range filters {
		for _, filter := range filterChunk {
			for _, fref := range filter.frefs {
				if fref.weakGroups != nil {
					weakRefs = append(weakRefs, &weakAliasFieldRef{filter})
				}
			}
		}
	}
	return weakRefs
}

func (w *weakAliasFieldRef) Ref() *fieldAliasRef {
	// Since we have checked that all
	return w.filter.frefs[0]
}

func (w *weakAliasFieldRef) Level() ErrorLevel {
	return ErrLevelFilter
}

func (w *weakAliasFieldRef) Resolve(fg *FieldGroup) {
	for _, fref := range w.filter.frefs {
		fref.Resolve(fg)
	}
	w.filter.Object = fg.Object
}
