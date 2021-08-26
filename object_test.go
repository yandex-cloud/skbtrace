package skbtrace

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

const defaultCastTmpl = "{{ .Dst }} = {{ .Src }}"

var testObjectsAB = []*Object{
	{Variable: "$a", Casts: map[string]string{"a": defaultCastTmpl}},
	{Variable: "$b", Casts: map[string]string{"$a": defaultCastTmpl}},
}
var testFieldGroupA = []*FieldGroup{
	{Object: "$a", Fields: []*Field{{Name: "a1"}}},
}

func TestBuildCastStructs(t *testing.T) {
	prog := NewProgram()
	probe := &Probe{Args: map[string]string{"a": "arg0"}}
	b := NewBuilder()
	b.AddObjects(testObjectsAB)

	t.Run("CastFromArg", func(t *testing.T) {
		block := prog.AddProbeBlock("", probe)
		block2, err := b.getBlockWithObject(block, "$a")

		require.NoError(t, err)
		assert.Equal(t, block2, block)
		assert.ElementsMatch(t, block2.Statements, []Statement{
			Stmt("$a = arg0"),
		})
	})

	t.Run("CastFromArgTwice", func(t *testing.T) {
		block := prog.AddProbeBlock("", probe)
		block2, err := b.getBlockWithObject(block, "$b")

		require.NoError(t, err)
		assert.Equal(t, block2, block)
		assert.ElementsMatch(t, block2.Statements, []Statement{
			Stmt("$a = arg0"),
			Stmt("$b = $a"),
		})
	})

	t.Run("CastReuseBlock", func(t *testing.T) {
		block := prog.AddProbeBlock("", probe)

		block2, err := b.getBlockWithObject(block, "$a")
		require.NoError(t, err)

		block3, err := b.getBlockWithObject(block, "$a")
		require.NoError(t, err)

		assert.Equal(t, block2, block)
		assert.Equal(t, block3, block)
		assert.ElementsMatch(t, block2.Statements, []Statement{
			Stmt("$a = arg0"),
		})
	})

	t.Run("CastNoPath", func(t *testing.T) {
		block := prog.AddProbeBlock("", probe)
		_, err := b.getBlockWithObject(block, "$c")
		assert.Error(t, err)
	})
}

func TestBuildCastLoop(t *testing.T) {
	prog := NewProgram()
	probe := &Probe{Args: map[string]string{}}
	b := NewBuilder()
	b.AddObjects([]*Object{
		{Variable: "$a", Casts: map[string]string{"$b": defaultCastTmpl}},
		{Variable: "$b", Casts: map[string]string{"$a": defaultCastTmpl}},
	})

	block := prog.AddProbeBlock("", probe)
	_, err := b.getBlockWithObject(block, "$a")
	assert.Error(t, err)
}

func TestBuildCastObjectSanityFilter(t *testing.T) {
	prog := NewProgram()
	probe := &Probe{Args: map[string]string{"a": "arg0", "c": "arg1"}}
	b := NewBuilder()

	b.AddObjects(testObjectsAB)
	b.AddFieldGroups(testFieldGroupA)
	b.AddObjects([]*Object{
		{Variable: "$c", SanityFilter: Filter{Object: "$a", Field: "a1", Op: "==", Value: "1"},
			Casts: map[string]string{"c": defaultCastTmpl}},
	})

	block := prog.AddProbeBlock("", probe)
	block2, err := b.getBlockWithObject(block, "$c")

	require.NoError(t, err)
	assert.NotEqual(t, block2, block)
	assert.ElementsMatch(t, block.Statements, []Statement{
		Stmt("$a = arg0"),
		stmtBlock(block2),
	})
	assert.Equal(t, "if ($a->a1 == 1)", block2.Preamble)
	assert.ElementsMatch(t, block2.Statements, []Statement{
		Stmt("$c = arg1"),
	})
}
