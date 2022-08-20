package skb

import (
	"bytes"
	"strconv"

	"github.com/yandex-cloud/skbtrace"
)

const (
	ProbeXmit = "kprobe:dev_queue_xmit"
	ProbeRecv = "kprobe:netif_receive_skb_internal"
)

// Offset of cb field in sk_buff which contains overlay control structure
const SkbCbOffset = "0x28"

const (
	DevNameAlias = "dev"
)

var skbHeaderFiles = []string{"linux/skbuff.h"}
var netdevHeaderFiles = []string{"linux/netdevice.h"}

var fieldsSkb = []*skbtrace.FieldGroup{
	{Row: "__skb_checksum", Fields: []*skbtrace.Field{
		{Name: "offset"},
		{Name: "len"}}},

	{Object: "$skb", Row: "layout", Fields: []*skbtrace.Field{
		{Name: "hroom", Converter: skbtrace.NewObjectConvExpr("%[1]s->data - %[1]s->head"),
			Help: "Head room -- space before packet data used to push extra headers"},
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

var objSkb = []*skbtrace.Object{
	// Raw sk buff pointer
	{Variable: "skb"},
	{Variable: "$skb", HeaderFiles: skbHeaderFiles,
		Casts: map[string]string{
			"skb": `{{ .Dst }} = ({{ StructKeyword }}sk_buff*) {{ .Src }}`,
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

var probesSkb = []*skbtrace.Probe{
	{Name: ProbeXmit, Aliases: []string{"xmit"}, Args: map[string]string{"skb": "arg0"},
		Help: "dev_queue_xmit() is called when kernel tries to put skb to a send queue of respective device"},
	{Name: ProbeRecv, Aliases: []string{"recv"}, Args: map[string]string{"skb": "arg0"},
		Help: "netif_receive_skb_internal() is called when kernel receives a packet"},
	{Name: "kprobe:kfree_skb", Aliases: []string{"free"}, Args: map[string]string{"skb": "arg0"},
		Help: "all packets are freed by kfree_skb()"},

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

func RegisterSkb(b *skbtrace.Builder) {
	b.AddObjects(objSkb)
	b.AddProbes(probesSkb)
	b.AddFieldGroups(fieldsSkb)

	b.AddCastFunction("SkbCbOffset", func() string { return SkbCbOffset })
}
