package skbtrace

func newProbeBuildError(probeName string, err error) *errorImpl {
	return newErrorf(ErrLevelProbe, probeName, err, "error building probe")
}

type Probe struct {
	// Name of the probe in BPFTrace format of "provider:name"
	Name string

	// List of aliases which could be used in command line
	Aliases []string

	// Context contains initial mapping untyped variable names to probe raw arguments
	Args map[string]string

	// Help string dumped by probes command
	Help string
}

func (b *Builder) addProbeBlock(
	prog *Program, probeName string, filters [][]*ProcessedFilter,
) (*Block, *Block, error) {
	if probeName == "" {
		return nil, nil, newCommonError(ErrLevelProbe, "", ErrMsgNotSpecified)
	}

	probe, ok := b.probeMap[probeName]
	if !ok {
		return nil, nil, newCommonError(ErrLevelProbe, probeName, ErrMsgNotFound)
	}

	probeBlock := prog.AddProbeBlock(probe.Name, probe)
	block, err := b.wrapFilters(probeBlock, filters)
	return probeBlock, block, err
}
