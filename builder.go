package skbtrace

import (
	"fmt"
	"strings"
	"text/template"
)

// Builder is a central object in skbtrace: it accumulates all knowledge
// on probes, objects accessible from them and their fields and then
// builds a trace using one of the Build() methods.
type Builder struct {
	objectList []*Object
	objectMap  map[string]*Object

	fieldGroupList []*FieldGroup
	fieldGroupMap  map[string][]*FieldGroup
	fieldObjectMap map[string][]*fieldAliasRef
	fieldAliasMap  map[string]*fieldAliasRef

	probeList []*Probe
	probeMap  map[string]*Probe

	castFunctionMap template.FuncMap

	globalVars map[string]Expression

	structDefs map[string]*StructDef
}

// Constructs a new trace script builder
func NewBuilder() *Builder {
	return &Builder{
		objectMap:       make(map[string]*Object),
		fieldGroupMap:   make(map[string][]*FieldGroup),
		fieldObjectMap:  make(map[string][]*fieldAliasRef),
		fieldAliasMap:   make(map[string]*fieldAliasRef),
		probeMap:        make(map[string]*Probe),
		castFunctionMap: make(template.FuncMap),
		globalVars:      make(map[string]Expression),
		structDefs:      make(map[string]*StructDef),
	}
}

func (b *Builder) Probes() []*Probe {
	return b.probeList
}

func (b *Builder) Objects() []*Object {
	return b.objectList
}

func (b *Builder) FieldGroups() []*FieldGroup {
	return b.fieldGroupList
}

// AddProbes registers probes and its aliases (including k: and kr: shortcuts)
// within a builder.
// Should be called on program start: might panic.
func (b *Builder) AddProbes(probes []*Probe) {
	for _, p := range probes {
		names := append(p.Aliases, p.Name)
		if strings.HasPrefix(p.Name, "kprobe:") {
			names = append(names, "k"+p.Name[6:])
		}
		if strings.HasPrefix(p.Name, "kretprobe:") {
			names = append(names, "kr"+p.Name[9:])
		}

		for _, name := range names {
			if _, ok := b.objectMap[name]; ok {
				panic(fmt.Sprintf("Probe '%s' is already registered", name))
			}

			b.probeMap[name] = p
		}
		b.probeList = append(b.probeList, p)
	}
}

// AddFieldGroups registers fields grouped by roes they're dumped to
// within a builder.
// Should be called on program start: might panic.
func (b *Builder) AddFieldGroups(fieldGroups []*FieldGroup) {
	for _, fg := range fieldGroups {
		for _, field := range fg.Fields {
			fref := &fieldAliasRef{fg: fg, field: field}
			b.fieldObjectMap[fg.Object] = append(b.fieldObjectMap[fg.Object], fref)
			if field.Alias == "" {
				continue
			}

			aliasName := field.Alias
			if len(fg.FieldAliasPrefix) > 0 {
				aliasName = fmt.Sprintf("%s-%s", fg.FieldAliasPrefix, aliasName)
			}

			if oldFref, ok := b.fieldAliasMap[aliasName]; ok {
				if field.WeakAlias {
					if oldFref.fg != nil {
						oldFref.weakGroups = append(oldFref.weakGroups, oldFref.fg)
						oldFref.fg = nil
					}

					oldFref.weakGroups = append(oldFref.weakGroups, fref.fg)
					continue
				}

				panic(fmt.Sprintf("Field alias '%s' is already registered", aliasName))
			}
			b.fieldAliasMap[aliasName] = fref
		}

		b.fieldGroupMap[fg.Row] = append(b.fieldGroupMap[fg.Row], fg)
		b.fieldGroupList = append(b.fieldGroupList, fg)
	}
}

// AddFieldGroupTemplate renders multiple filter group rows based on
// template fgBase which has all fields filled except fields.
// See AddFieldGroups.
func (b *Builder) AddFieldGroupTemplate(fgBase FieldGroup, rows [][]*Field) {
	for _, row := range rows {
		fg := fgBase
		fg.Fields = row
		b.AddFieldGroups([]*FieldGroup{&fg})
	}
}

// AddObjects registers object (structure) descriptions within a builder.
// Should be called on program start: might panic.
func (b *Builder) AddObjects(objects []*Object) {
	for _, obj := range objects {
		if obj.SanityFilter.Object != "" && obj.Variable == obj.SanityFilter.Object {
			panic(fmt.Sprintf("Object '%s' uses sanity filter referring itself."+
				" Should be replaced with field-based sanity filter", obj.Variable))
		}

		if _, ok := b.objectMap[obj.Variable]; ok {
			panic(fmt.Sprintf("Object '%s' is already registered", obj.Variable))
		}

		b.objectMap[obj.Variable] = obj
		b.objectList = append(b.objectList, obj)
	}
}

// AddObjectCasts merges casts supplied by objCasts into already registered
// objects
// Should be called on program start: might panic.
func (b *Builder) AddObjectCasts(objCasts []*Object) {
	for _, objCast := range objCasts {
		obj, ok := b.objectMap[objCast.Variable]
		if !ok {
			panic(fmt.Sprintf("Object '%s' is not registered", objCast.Variable))
		}

		origCasts := obj.Casts
		obj.Casts = make(map[string]string)
		for src, tmpl := range origCasts {
			obj.Casts[src] = tmpl
		}
		for src, tmpl := range objCast.Casts {
			obj.Casts[src] = tmpl
		}
	}
}

// AddCastFunction registers function accessible from casts.
func (b *Builder) AddCastFunction(name string, f interface{}) {
	b.castFunctionMap[name] = f
}

// SetFeatures initializes builder based on host BPFTrace version
func (b *Builder) SetFeatures(mask FeatureFlagMask) {
	b.setUseStructKeyword(mask.Supports(FeatureStructKeyword))
}

func (b *Builder) setUseStructKeyword(useKeyword bool) {
	var keyword string
	if useKeyword {
		keyword = "struct "
	}

	b.castFunctionMap["StructKeyword"] = func() (string, error) {
		return keyword, nil
	}
}

// Registers globally available variables and expressions to fetch them.
// Should be called on program start: might panic.
func (b *Builder) AddGlobalVars(vars map[string]Expression) {
	for varName, expr := range vars {
		if _, ok := b.globalVars[varName]; ok {
			panic(fmt.Sprintf("Global variable '%s' is already registered", varName))
		}

		b.globalVars[varName] = expr
	}
}

// Registers struct type definition and parses its string.
// See StructDef for more info.
func (b *Builder) AddStructDef(typeName string, rawText string) {
	if oldDef, ok := b.structDefs[typeName]; ok {
		if oldDef.rawText == rawText {
			return
		}
		panic(fmt.Sprintf("Struct definition '%s' is already registered", typeName))
	}

	b.structDefs[typeName] = &StructDef{
		TypeName: typeName,
		Text:     strings.Split(rawText, "\n"),
		rawText:  rawText,
	}
}
