package skbtrace

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
)

// Custom structure definition for use in bpftrace script. They're useful
// when header file is not part of linux-headers package, or when
// bpftrace cannot handle some aspects of the type properly, such as
// arrays or bit fields
// NOTE: Raw struct defs should be anonymous structs, as they're wrapped
// into outer structure due to bpftrace parser not handling correctly
// GCC attributes at top level
// NOTE: StructDef is not created directly, but spawned by AddStructDef
type StructDef struct {
	// Name of the structure
	TypeName string

	// Text of struct definition split by line
	Text []string

	// Cached raw text for comparisons
	rawText string
}

// Object is a representation of an object that can be accessed within
// a probe and contains neccessary actions (casts) to infer it,
// sanity filters to check its correctness and typing information
type Object struct {
	// Name of the variable used for this object
	Variable string

	// List of include files which should be included in BPFTrace
	// script for this type to become available in BPFTrace
	HeaderFiles []string

	// Struct definitions to be embedded into codes
	StructDefs []string

	// SanityFilter allows to specify a filter referring an external object
	SanityFilter Filter

	// Maps object variable names this object is inferrable from to
	// templates (see CastTemplateArgs for template arguments)
	Casts map[string]string
}

type CastTemplateArgs struct {
	// Variable the object is casted from
	Src string

	// Name of the variable object is assigned to
	Dst string
}

type objectCast struct {
	src      string
	srcObj   *Object
	dst      string
	castTmpl string
}

// getBlockWithObject returns block which has specified object in its context either from
// already existing child blocks, or by building nested blocks with type casts necessary to
// access the object
func (b *Builder) getBlockWithObject(
	block *Block, objName string,
) (*Block, error) {
	// For objectless fields they should be available in top-level block,
	// of not, generateFieldExpression() will correct us
	if len(objName) == 0 {
		return block, nil
	}

	// Special case for tracepoint: probes - allow to dump its args
	if objName == "args" {
		if !strings.HasPrefix(block.probe.Name, "tracepoint:") {
			return nil, newErrorf(ErrLevelProbe, block.probe.Name, nil,
				"probe is not a tracepoint, hence it cannot have args")
		}
		return block, nil
	}

	// If cast path was already built, walk block tree recursively, and
	// find corresponding block. Note that this might reorder print statements
	// but that it is for a good
	block2 := block.findBlockWithObject(objName)
	if block2 != nil {
		return block2, nil
	}

	// If object is not available yet, start searching for it
	obj, ok := b.objectMap[objName]
	if !ok {
		return nil, newCommonError(ErrLevelObject, objName, ErrMsgNotFound)
	}

	path, err := b.findCastPath(block.context, block.probe, obj,
		make([]objectCast, 0), make(BlockContext))
	if err != nil || len(path) == 0 {
		return nil, newErrorf(ErrLevelObject, objName, err,
			"cannot be inferred from context")
	}

	dstObj := obj
	for i := len(path) - 1; i >= 0; i-- {
		cast := path[i]
		if dstObj != nil && dstObj.SanityFilter.Object != "" {
			block, err = b.wrapObjectSanityFilters(block, dstObj.SanityFilter)
			if err != nil {
				return nil, err
			}
		}

		b.addStructDefsAndHeaders(block.prog, dstObj)
		stmt, err := b.buildCastStatement(cast, dstObj)
		if err != nil {
			err = newErrorf(ErrLevelObject, obj.Variable, err,
				"error in template for cast from '%s' to '%s'", cast.src, cast.dst)
			return nil, err
		}
		block.Add(stmt)

		// Avoid printing invalid data using sanity filters: wrap print statements into ifs
		sanityFilters := b.processFieldSanityFilters(cast.dst)
		block, err = b.addFilterBlock(block, sanityFilters)
		if err != nil {
			return nil, newErrorf(ErrLevelObject, objName, err,
				"cannot build per-field sanity filters")
		}

		// Register variable in context only after sanity filter
		block.context[cast.dst] = struct{}{}

		dstObj = cast.srcObj
	}

	err = b.addStructDefsAndHeaders(block.prog, dstObj)
	if err != nil {
		return nil, newErrorf(ErrLevelObject, objName, err,
			"cannot add headers and struct definitions")
	}

	return block, nil
}

// Renders a block wrapped into an object sanity filter
func (b *Builder) wrapObjectSanityFilters(block *Block, filter Filter) (*Block, error) {
	block, err := b.getBlockWithObject(block, filter.Object)
	if err != nil {
		return nil, err
	}

	sanityFilters, err := b.processFilter(&filter)
	if err != nil {
		return nil, err
	}

	return b.addFilterBlock(block, sanityFilters)
}

func (b *Builder) addStructDefsAndHeaders(prog *Program, dstObj *Object) error {
	if dstObj == nil {
		return nil
	}

	for _, hdrFile := range dstObj.HeaderFiles {
		prog.HeaderFiles[hdrFile] = struct{}{}
	}
	for _, typeName := range dstObj.StructDefs {
		structDef, ok := b.structDefs[typeName]
		if !ok {
			return newCommonError(ErrLevelStructDef, typeName, ErrMsgNotFound)
		}

		prog.StructDefs[typeName] = structDef
	}

	return nil
}

// Renders a text template provided in cast to convert source to destination object
func (b *Builder) buildCastStatement(cast objectCast, obj *Object) (stmt Statement, err error) {
	buf := bytes.NewBuffer(nil)
	args := &CastTemplateArgs{Src: cast.src, Dst: cast.dst}

	tmpl := template.New(fmt.Sprintf("%s-%s", cast.src, cast.dst))
	tmpl, err = tmpl.Funcs(b.castFunctionMap).Parse(cast.castTmpl)
	if err != nil {
		return
	}

	err = tmpl.Execute(buf, args)
	if err != nil {
		return
	}

	stmt = Stmt(buf.String())
	return
}

// Try to find shortest path between casts provided by probe (or already created)
// recursively using BFS. So if probe has raw skb and user requests net device we will
// produce path raw skb -> skb and then skb -> net dev.
func (b *Builder) findCastPath(
	ctx BlockContext, probe *Probe, obj *Object,
	path []objectCast, tmpCtx BlockContext,
) ([]objectCast, error) {
	for src, castTmpl := range obj.Casts {
		// The source is present in probe arguments
		// (but this needs replacing raw variable reference)
		if arg, ok := probe.Args[src]; ok {
			path = append(path, objectCast{arg, b.objectMap[src], obj.Variable, castTmpl})
			return path, nil
		}

		// The path is found as source is already present, return it
		if _, ok := ctx[src]; ok {
			path = append(path, objectCast{src, b.objectMap[src], obj.Variable, castTmpl})
			return path, nil
		}
	}

	for src, castTmpl := range obj.Casts {
		// Avoid looping in casts if we already tried this object
		if _, ok := tmpCtx[src]; ok {
			continue
		}

		srcObj, ok := b.objectMap[src]
		if !ok {
			return nil, newErrorf(ErrLevelObject, src, nil, "unexpected source in cast")
		}

		tmpCtx[src] = struct{}{}
		newPath := append(path, objectCast{src, srcObj, obj.Variable, castTmpl})
		fullPath, err := b.findCastPath(ctx, probe, srcObj, newPath, tmpCtx)
		if err != nil {
			return fullPath, newErrorf(ErrLevelObject, obj.Variable, err, "cast error")
		}

		if fullPath != nil {
			return fullPath, nil
		}

		delete(tmpCtx, src)
	}

	return nil, nil
}
