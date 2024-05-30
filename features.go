package skbtrace

import (
	"bytes"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/exp/maps"
)

// FeatureComponent groups features by components they are implemented by.
// FeatureComponentExternal can be used by commands built on top of skbtrace which
// can use customized kernel module versioned separately from kernel version.
type FeatureComponent int

const (
	FeatureComponentKernel FeatureComponent = iota
	FeatureComponentBPFTrace
	FeatureComponentExternal

	FeatureComponentCount
)

type featureState byte

const (
	featureAuto featureState = iota
	featureForceEnable
	featureForceDisable
)

type FeatureFlagMask struct {
	bits *big.Int
}

type Version struct {
	// Open-Source derived versions
	Major    int
	Submajor int
	Minor    int

	// NOTE: Yandex Cloud derivatives use build numbers and do not alter open-source versions
	Build int
	Date  int
}

type VersionProvider interface {
	Get() ([]byte, error)
	Parse(verBytes []byte) (Version, error)
	GetDefault() Version
}

func NewVersionFromMatches(matches [][]byte) (ver Version, err error) {
	for i, ptr := range []*int{&ver.Major, &ver.Submajor, &ver.Minor, &ver.Build, &ver.Date} {
		if i >= len(matches) {
			break
		}

		*ptr, err = strconv.Atoi(string(matches[i]))
		if err != nil {
			return ver, fmt.Errorf("error parsing version component #%d: %w", i, err)
		}
	}
	return ver, nil
}

func (v Version) EqualOrNewer(v2 Version) bool {
	if v.Major != v2.Major {
		return v.Major > v2.Major
	}
	if v.Submajor != v2.Submajor {
		return v.Submajor > v2.Submajor
	}
	if v.Minor != v2.Minor {
		return v.Minor > v2.Minor
	}

	if v.Build != v2.Build {
		return v.Build > v2.Build
	}
	return v.Date >= v2.Date
}

func (v Version) String() string {
	b := bytes.NewBuffer(nil)
	fmt.Fprintf(b, "%d.%d.%d", v.Major, v.Submajor, v.Minor)
	if v.Build > 0 {
		fmt.Fprintf(b, "-%d", v.Build)
		if v.Date > 0 {
			fmt.Fprintf(b, ".%06d", v.Date)
		}
	}
	return b.String()
}

type Feature struct {
	Component  FeatureComponent
	Name       string
	Help       string
	Commit     string
	MinVersion Version

	// flag is assigned after registering feature in init
	flag int
}

var knownFeatures [FeatureComponentCount][]*Feature

func RegisterFeatures(features ...*Feature) {
	for _, feature := range features {
		component := feature.Component
		feature.flag = len(knownFeatures[component]) + 1
		knownFeatures[component] = append(knownFeatures[component], feature)
	}
}

func GetKnownFeatures(component FeatureComponent) []*Feature {
	return knownFeatures[component]
}

type FeatureComponentSpec struct {
	Component FeatureComponent
	Provider  VersionProvider
}

// ProcessFeatures produces feature mask for the current setup. Default is detection
// by a version, but additionally some features can be disabled (if preceded with !) or
// enabled via mask argument containing names of the features separated by commas.
func (spec FeatureComponentSpec) ProcessFeatures(verArg, maskArg string) (mask FeatureFlagMask, err error) {
	ver, err := getVersion(verArg, spec.Provider)
	if err != nil {
		return FeatureFlagMask{}, err
	}

	var forcedState map[string]featureState
	if maskArg != "" {
		forcedState, err = parseMaskArgument(maskArg)
		if err != nil {
			return FeatureFlagMask{}, err
		}
	}

	bits := big.NewInt(0)
loop:
	for _, feature := range knownFeatures[spec.Component] {
		if forcedState != nil {
			switch forcedState[feature.Name] {
			case featureForceEnable:
				bits.SetBit(bits, int(feature.flag), 1)
				fallthrough
			case featureForceDisable:
				delete(forcedState, feature.Name)
				continue loop
			case featureAuto:
				// Handle auto value: compare versions
			}
		}

		if ver.EqualOrNewer(feature.MinVersion) {
			bits.SetBit(bits, int(feature.flag), 1)
		}
	}

	if len(forcedState) > 0 {
		return FeatureFlagMask{}, fmt.Errorf(
			"unrecognized features specified in mask: %s",
			strings.Join(maps.Keys(forcedState), ","))
	}

	return FeatureFlagMask{bits: bits}, nil
}

func getVersion(verArg string, provider VersionProvider) (ver Version, err error) {
	var verBytes []byte
	if verArg == "" {
		verBytes, err = provider.Get()
		if err != nil {
			return provider.GetDefault(), err
		}
	} else {
		verBytes = []byte(verArg)
	}

	return provider.Parse(verBytes)
}

func parseMaskArgument(maskArg string) (map[string]featureState, error) {
	tokens := strings.Split(maskArg, ",")
	stateMap := make(map[string]featureState, len(tokens))
	for _, token := range tokens {
		state := featureForceEnable
		if strings.HasPrefix(token, "!") {
			token = token[1:]
			state = featureForceDisable
		}

		if _, hasState := stateMap[token]; hasState {
			return nil, fmt.Errorf(
				"cannot parse feature mask: feature %q is already specified", token)
		}
		stateMap[token] = state
	}
	return stateMap, nil
}

func (mask FeatureFlagMask) Supports(feature *Feature) bool {
	if feature.flag == 0 {
		panic(fmt.Errorf("trying to check feature %q that wasn't registered", feature.Name))
	}

	return mask.bits.Bit(feature.flag) == 1
}

var reKernelVersion = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

type KernelVersionProvider struct{}

func (k *KernelVersionProvider) Get() ([]byte, error) {
	var utsname syscall.Utsname
	if err := syscall.Uname(&utsname); err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(make([]byte, 0, len(utsname.Version)))
	for _, r := range utsname.Release {
		if r == 0 {
			break
		}
		buf.WriteByte(byte(r))
	}
	return buf.Bytes(), nil
}

func (k *KernelVersionProvider) Parse(verBytes []byte) (Version, error) {
	matches := reKernelVersion.FindSubmatch(verBytes)
	if len(matches) < 4 {
		return safeDefaultVersion, fmt.Errorf(
			"not enough numeric components in version %q, at least 3 are needed", verBytes)
	}

	return NewVersionFromMatches(matches[1:])
}

func (k *KernelVersionProvider) GetDefault() Version {
	return Version{Major: 4, Submajor: 14}
}
