package skbtrace

import (
	"errors"
	"strings"
)

func newProbeBuildError(probeName string, err error) *errorImpl {
	return newErrorf(ErrLevelProbe, probeName, err, "error building probe")
}

type Probe struct {
	// Name of the probe in BPFTrace format of "provider:name"
	Name string

	// ReturnName contains explicit name that denotes end of the context probe execution
	ReturnName string

	// List of aliases which could be used in command line
	Aliases []string

	// Context contains initial mapping untyped variable names to probe raw arguments
	Args map[string]string

	// Help string dumped by probes command
	Help string
}

func (b *Builder) addProbeBlock(
	prog *Program, probeName string, isReturn bool, filters [][]*ProcessedFilter,
) (*Block, *Block, error) {
	if probeName == "" {
		return nil, nil, newCommonError(ErrLevelProbe, "", ErrMsgNotSpecified)
	}

	probe, ok := b.probeMap[probeName]
	if !ok {
		return nil, nil, newCommonError(ErrLevelProbe, probeName, ErrMsgNotFound)
	}

	name := probe.Name
	if isReturn {
		retName, err := probe.ReturnProbe()
		if err != nil {
			return nil, nil, err
		}
		name = retName
	}

	probeBlock := prog.AddProbeBlock(name, probe)
	block, err := b.wrapFilters(probeBlock, filters)
	return probeBlock, block, err
}

func (p *Probe) ReturnProbe() (string, error) {
	if p.ReturnName != "" {
		return p.ReturnName, nil
	}

	if strings.HasPrefix(p.Name, "k:") {
		return "kr:" + p.Name[2:], nil
	} else if strings.HasPrefix(p.Name, "kprobe:") {
		return "kretprobe:" + p.Name[7:], nil
	}

	return "", newProbeBuildError(p.Name, errors.New("can't deduce return probe name"))
}
