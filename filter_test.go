package skbtrace

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var taskFields = []*FieldGroup{
	{Row: "task", Fields: []*Field{{Name: "pid"}}},
}

var ipFields = []*FieldGroup{
	{Row: "task", Object: "$iph", Fields: []*Field{
		{Name: "ttl"},
		{Name: "saddr", Alias: "src", Preprocessor: fppPtonInet}}},
}

func fppPtonInet(op, value string) (string, error) {
	if op == "==" && value == "127.0.0.1" {
		return "0x100007f", nil
	}
	return value, nil
}

func TestFilterParse(t *testing.T) {
	b := NewBuilder()
	b.AddFieldGroups(taskFields)
	b.AddFieldGroups(ipFields)

	t.Run("SimpleFilter", func(t *testing.T) {
		f, err := b.parseFilter("$iph->ttl >= 50")
		require.NoError(t, err)
		require.Len(t, f, 1)

		assert.Equal(t, Filter{"$iph", "ttl", ">=", "50"}, f[0].Filter)
	})

	t.Run("AliasFilter", func(t *testing.T) {
		f, err := b.parseFilter("src == 127.0.0.1")
		require.NoError(t, err)
		require.Len(t, f, 1)

		assert.Equal(t, Filter{"$iph", "saddr", "==", "127.0.0.1"}, f[0].Filter)

		prog := NewProgram()
		block2, err := b.addFilterBlock(prog.AddIntervalBlock(time.Second), f)

		assert.Equal(t, "if ($iph->saddr == 0x100007f)", block2.Preamble)
	})

	t.Run("PIDFilter", func(t *testing.T) {
		f, err := b.parseFilter("pid == 100500")
		require.NoError(t, err)
		require.Len(t, f, 1)

		assert.Equal(t, Filter{"", "pid", "==", "100500"}, f[0].Filter)
	})
}
