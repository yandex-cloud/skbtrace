package skbtrace

// Helper for weak alias filters: picks whichever object is more likely
// to appear based on other filters and print statements
type builderObjectSet map[string]struct{}

type weakAliasRef interface {
	Ref() *fieldAliasRef
	Level() ErrorLevel

	Resolve(fg *FieldGroup)
}

func (b *Builder) newBuildObjectSet(
	filters [][]*ProcessedFilter, rows []string, hints []string,
) builderObjectSet {
	boSet := make(builderObjectSet)
	b.deduceFilterObjects(boSet, filters)
	b.deduceDumpObjects(boSet, rows)
	b.deduceDumpObjects(boSet, hints)
	return boSet
}

func (b *Builder) deduceDumpObjects(boSet builderObjectSet, rows []string) {
	if len(rows) == 0 {
		return
	}

	for _, row := range rows {
		if fgList, ok := b.fieldGroupMap[row]; ok {
			boSet[fgList[0].Object] = struct{}{}
		}
	}
}

func (b *Builder) deduceFilterObjects(boSet builderObjectSet, filters [][]*ProcessedFilter) {
	for _, filterChunk := range filters {
		for _, filter := range filterChunk {
			if filter.fref.fg == nil {
				continue
			}

			boSet[filter.fref.fg.Object] = struct{}{}
		}
	}
}

// resolveWeakAliasRefs resolves field references in processed filters which do not have
// pointer to FieldGroup for filters which use fields with field aliases for which
// source object is not known due to weak aliasing logic. boSet contains set of objects
// which will be produced in this trace script due to dump rows, other filters, keys, etc.
// If deduction is failed due to lack of respective object hints, error is returned
func (b *Builder) resolveWeakAliasRefs(refs []weakAliasRef, boSet builderObjectSet) error {
loop:
	for _, ref := range refs {
		for _, fg := range ref.Ref().weakGroups {
			if _, ok := boSet[fg.Object]; ok {
				ref.Resolve(fg)
				continue loop
			}
		}

		return newErrorf(ref.Level(), ref.Ref().field.Name, nil,
			"object cannot be deduced for weak alias from rows, filters and hints")
	}

	return nil
}
