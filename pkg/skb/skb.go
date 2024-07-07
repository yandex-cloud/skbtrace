package skb

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/yandex-cloud/skbtrace"
)

const (
	ProbeXmit = "kprobe:dev_queue_xmit"
	ProbeRecv = "kprobe:__netif_receive_skb_core"
)

// Offset of cb field in sk_buff which contains overlay control structure
const SkbCbOffset = "0x28"

const (
	DevNameAlias = "dev"
)

var skbHeaderFiles = []string{"linux/skbuff.h"}
var netdevHeaderFiles = []string{"linux/netdevice.h"}

var freeSkbReasonFeature = &skbtrace.Feature{
	Component: skbtrace.FeatureComponentKernel,
	Name:      "kfree_skb_reason",
	Help:      "kfree_skb_reason is a new version of packet free that provides numeric reason for packet drop",

	// use LTS version commit here
	Commit:     "5158e18225c06f39cde0176a431db6e60f52ebc2",
	MinVersion: skbtrace.Version{Major: 5, Submajor: 15, Minor: 93},
}

var recvSkbRefFeature = &skbtrace.Feature{
	Component: skbtrace.FeatureComponentKernel,
	Name:      "__netif_receive_skb_core:ref",
	Help:      "__netif_receive_skb_core receives skb by sk_buff**",

	// use LTS version commit here
	Commit:     "c0bbbdc32febd4f034ecbf3ea17865785b2c0652",
	MinVersion: skbtrace.Version{Major: 5, Submajor: 10, Minor: 65},
}

func newFieldsSkb(featureMask skbtrace.FeatureFlagMask) []*skbtrace.FieldGroup {
	return []*skbtrace.FieldGroup{
		{Row: "__skb_checksum", Fields: []*skbtrace.Field{
			{Name: "offset"},
			{Name: "len"}}},

		{Object: "$skb", Row: "layout", Fields: []*skbtrace.Field{
			{Name: "hroom",
				Converter: skbtrace.NewObjectBinOpConvExpr("%[1]s->data", "%[1]s->head", "-", skbtrace.TUInt64, featureMask),
				Help:      "Head room -- space before packet data used to push extra headers"},
			{Name: "hlen", Converter: skbtrace.NewObjectConvExpr("%[1]s->len - %[1]s->data_len"),
				Help: "Head length -- space used by headers before data pointer"},
			{Name: "mac_header", FmtKey: "mac hoff"},
			{Name: "network_header", FmtKey: "net hoff"},
			{Name: "transport_header", FmtKey: "trans hoff"},
		}},
		{Object: "$skb", Row: "layout", Fields: []*skbtrace.Field{
			{Name: "len"},
			{Name: "data_len"},
			{Name: "troom", Converter: skbtrace.NewObjectConvExpr("%[1]s->tail - %[1]s->end")},
			{Name: "truesize"},
		}},

		{Object: "$skb", Row: "checksum", Fields: []*skbtrace.Field{
			{Name: "ip_summed", Converter: skbtrace.NewConvBitfieldExpr(5, 0x3)},
			{Name: "csum_start", FmtKey: "start"},
			{Name: "csum_offset", FmtKey: "off"},
		}},

		{Object: "$skbsi", Row: "flags", Fields: []*skbtrace.Field{
			{Name: "page_offset", FmtKey: "pgoff"},
			{Name: "size", FmtKey: "size"},
		}},

		{Object: "$skbsi", Row: "gso", Fields: []*skbtrace.Field{
			{Name: "nr_frags"},
			{Name: "gso_size"},
			{Name: "gso_segs"},
			{Name: "gso_type"},
		}},

		{Object: "$netdev", Row: "netdev", Fields: []*skbtrace.Field{
			{Name: "name", Alias: DevNameAlias, FmtSpec: "%s"},
			{Name: "mtu"},
			{Name: "state", FmtSpec: "%x"},
			{Name: "features", FmtSpec: "%x"}}},
	}
}

var objSkb = []*skbtrace.Object{
	// Sk buff double ref
	{Variable: "pskb"},
	{Variable: "$pskb", HeaderFiles: skbHeaderFiles,
		Casts: map[string]string{
			"pskb": `{{ .Dst }} = ({{ StructKeyword }}sk_buff**) {{ .Src }}`,
		}},

	// Raw sk buff pointer
	{Variable: "skb"},
	{Variable: "$skb", HeaderFiles: skbHeaderFiles,
		Casts: map[string]string{
			"skb":   `{{ .Dst }} = ({{ StructKeyword }}sk_buff*) {{ .Src }}`,
			"$pskb": `{{ .Dst }} = *{{ .Src }}`,
		}},

	// Skb control buffer: a 48-byte part of skb structure which is used
	// internally by various overlay. Its contents are opaque to skbtrace,
	// but might be revealed by clients of the library
	{Variable: "$skbcb",
		Casts: map[string]string{
			"skb": `{{ .Dst }} = {{ .Src }} + {{ SkbCbOffset }}`,
		}},

	{Variable: "$skbsi",
		Casts: map[string]string{
			// NOTE: assumes NET_SKBUFF_DATA_USES_OFFSET
			"$skb": `{{ .Dst }} = ({{ StructKeyword }}skb_shared_info*) ({{ .Src }}->head + {{ .Src }}->end)`,
		}},

	{Variable: "$netdev", HeaderFiles: netdevHeaderFiles,
		Casts: map[string]string{
			"$skb": `{{ .Dst }} = {{ .Src }}->dev`,
		}},
}

var xmitProbeSkb = &skbtrace.Probe{
	Name: ProbeXmit, Aliases: []string{"xmit"}, Args: map[string]string{"skb": "arg0"},
	Help: "dev_queue_xmit() is called when kernel tries to put skb to a send queue of respective device"}

func newRecvSkbProbe(mask skbtrace.FeatureFlagMask) *skbtrace.Probe {
	skbArg := "skb"
	if mask.Supports(recvSkbRefFeature) {
		skbArg = "pskb"
	}

	return &skbtrace.Probe{
		Name: ProbeRecv, Aliases: []string{"recv"}, Args: map[string]string{skbArg: "arg0"},
		Help: "__netif_receive_skb_core() is called when kernel receives a packet"}
}

func newFreeSkbProbe(mask skbtrace.FeatureFlagMask) *skbtrace.Probe {
	funcName := "kfree_skb"
	args := map[string]string{"skb": "arg0"}
	if mask.Supports(freeSkbReasonFeature) {
		funcName = "kfree_skb_reason"
		args["reason"] = "arg1"
	}

	return &skbtrace.Probe{
		Name: "kprobe:" + funcName, Aliases: []string{"free"}, Args: args,
		Help: fmt.Sprintf("all packets are freed by %s()", funcName)}
}

var extProbesSkb = []*skbtrace.Probe{
	// Checksumming and some offload functions
	{Name: "kprobe:__skb_checksum", Args: map[string]string{"skb": "arg0", "offset": "arg1", "len": "arg2"},
		Help: "__skb_checksum() is called when kernel computes checksum for a packet"},

	// GRO/GSO probes
	{Name: "kprobe:tcp_gso_segment", Args: map[string]string{"skb": "arg0"},
		Help: "tcp_gso_segment() is called when kernel executes GSO on TCP segment"},
	{Name: "kprobe:tcp_gro_receive", Args: map[string]string{"skb": "arg1"},
		Help: "tcp_gro_receive() is called when GRO tries to merge sk buffs"},
	{Name: "kprobe:tcp_gro_complete", Args: map[string]string{"skb": "arg0"},
		Help: "tcp_gro_complete() is called when GRO finishes setting merged sk buff"},
	{Name: "kprobe:__skb_gso_segment", Args: map[string]string{"skb": "arg0"},
		Help: "__skb_gso_segment() is called when device decides to apply GSO to sk buff"},

	// Some IPv4 probes
	{Name: "kprobe:ip_rcv", Args: map[string]string{"skb": "arg0"}},
	{Name: "kprobe:ip_defrag", Args: map[string]string{"skb": "arg1"}},
}

type DataCastBuilder struct {
	buf      *bytes.Buffer
	fieldSet bool
}

func NewDataCastBuilder(structType, headField string) *DataCastBuilder {
	buf := bytes.NewBufferString("{{ .Dst }} = ({{ StructKeyword }}")
	buf.WriteString(structType)
	buf.WriteString("*) ({{ .Src }}->")
	buf.WriteString(headField)

	return &DataCastBuilder{buf: buf}
}

func (dcb *DataCastBuilder) SetField(field string) *DataCastBuilder {
	if dcb.fieldSet {
		return dcb
	}
	dcb.fieldSet = true
	dcb.buf.WriteString(" + {{ .Src }}->")
	dcb.buf.WriteString(field)
	return dcb
}

func (dcb *DataCastBuilder) SetOuterOffset(offset int) *DataCastBuilder {
	dcb.SetField("mac_header")
	dcb.buf.WriteString(" + ")
	dcb.buf.WriteString(strconv.Itoa(offset))
	return dcb
}

func (dcb *DataCastBuilder) SetInnerHelpers(helpers ...string) *DataCastBuilder {
	dcb.SetField("mac_header")
	for _, helper := range helpers {
		dcb.buf.WriteString(" + {{ ")
		dcb.buf.WriteString(helper)
		dcb.buf.WriteString(" }}")
	}
	return dcb
}

func (dcb *DataCastBuilder) Build() string {
	dcb.buf.WriteString(")")
	return dcb.buf.String()
}

func RegisterSkb(b *skbtrace.Builder, bpfTraceFeatureMask, kernelFeatureMask skbtrace.FeatureFlagMask) {
	b.AddObjects(objSkb)
	b.AddProbes([]*skbtrace.Probe{
		xmitProbeSkb,
		newRecvSkbProbe(kernelFeatureMask),
		newFreeSkbProbe(kernelFeatureMask),
	})
	b.AddProbes(extProbesSkb)
	b.AddFieldGroups(newFieldsSkb(bpfTraceFeatureMask))

	b.AddCastFunction("SkbCbOffset", func() string { return SkbCbOffset })
}

func init() {
	skbtrace.RegisterFeatures(freeSkbReasonFeature, recvSkbRefFeature)
}
