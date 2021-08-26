package skb

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSkbDataCastBuilder(t *testing.T) {
	t.Run("Default", func(t *testing.T) {
		s := NewDataCastBuilder("iphdr").SetField("network_header").Build()
		assert.Equal(t, "{{ .Dst }} = ({{ StructKeyword }}iphdr*)"+
			" ({{ .Src }}->head + {{ .Src }}->network_header)", s)
	})

	t.Run("Outer", func(t *testing.T) {
		s := NewDataCastBuilder("iphdr").SetOuterOffset(14).Build()
		assert.Equal(t, "{{ .Dst }} = ({{ StructKeyword }}iphdr*)"+
			" ({{ .Src }}->head + {{ .Src }}->mac_address + 14)", s)
	})

	t.Run("Inner", func(t *testing.T) {
		s := NewDataCastBuilder("iphdr").SetInnerHelpers("OverlayHeaderLength").Build()
		assert.Equal(t, "{{ .Dst }} = ({{ StructKeyword }}iphdr*)"+
			" ({{ .Src }}->head + {{ .Src }}->mac_address + {{ OverlayHeaderLength }})", s)
	})
}
