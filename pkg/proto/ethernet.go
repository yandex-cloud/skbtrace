package proto

import (
	_ "embed"

	"github.com/yandex-cloud/skbtrace"
	"github.com/yandex-cloud/skbtrace/pkg/skb"
)

const (
	EthHdrLength = 14

	ethMacFmtSpec = "%02x:%02x:%02x:%02x:%02x:%02x"
)

// NOTE: printf is limited to 7 args, so report mac using multiple prints
var ethFieldGroups = []*skbtrace.FieldGroup{
	{Row: "eth", Object: "$eth_hdr", Fields: []*skbtrace.Field{
		{Name: "dst", FmtSpec: ethMacFmtSpec, Converter: convEthMac}}},
	{Row: "eth", Object: "$eth_hdr", Fields: []*skbtrace.Field{
		{Name: "src", FmtSpec: ethMacFmtSpec, Converter: convEthMac}}},
	{Row: "eth", Object: "$eth_hdr", Fields: []*skbtrace.Field{
		{Name: "protocol", FmtSpec: "0x%04x", Converter: skbtrace.ConvNtohs, Preprocessor: skbtrace.FppNtohs}}},
}

//go:embed headers/machdr.h
var macHdrDef string

var ethObjects = []*skbtrace.Object{
	{Variable: "$eth_hdr", HeaderFiles: headerFiles, StructDefs: []string{"machdr"},
		Casts: map[string]string{
			"$skb": skb.NewDataCastBuilder("machdr", "head").SetField("mac_header").Build(),
		}},
}

func convEthMac(obj, field string) ([]skbtrace.Statement, skbtrace.Expression) {
	var byteExprs []skbtrace.Expression
	for i := 0; i < 6; i++ {
		byteExprs = append(byteExprs, skbtrace.Exprf("%s[%d]", skbtrace.ExprField(obj, field), i))
	}
	return nil, skbtrace.ExprJoin(byteExprs)
}

func RegisterEth(b *skbtrace.Builder) {
	b.AddFieldGroups(ethFieldGroups)
	b.AddStructDef("machdr", macHdrDef)
	b.AddObjects(ethObjects)
}
