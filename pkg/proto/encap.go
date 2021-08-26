package proto

import (
	_ "embed"
	"errors"
	"fmt"
	"strconv"

	"github.com/yandex-cloud/skbtrace/pkg/skb"

	"github.com/yandex-cloud/skbtrace"
)

const (
	EncapProtoEth  = "eth"
	EncapProtoIp   = "ip"
	EncapProtoGre  = "gre"
	EncapProtoUdp  = "udp"
	EncapProtoMpls = "mpls"

	OverlayHeaderLengthFunc = "OverlayHeaderLength"
	BaseEncapHdrLength      = EthHdrLength + IpHdrMinLength
	UdpHdrLength            = 8
	GreHdrLength            = 4
	MplsHdrLength           = 4

	GreProtocolNumber = 47
	MplsOverUdpPort   = 6635
)

const (
	ObjIpHdrOuter   = "$out_iph"
	ObjUdpHdrOuter  = "$out_udph"
	ObjMplsHdrOuter = "$out_mplsh"
)

var encapFieldGroups = []*skbtrace.FieldGroup{
	{Row: "outer-mpls", Object: "$out_mplsh", Fields: []*skbtrace.Field{
		{Name: "word", Alias: "label", FmtKey: "label",
			Converter: convMplsLabel, FilterOperator: filtopMplsLabel}}},
}

var encapObj = []*skbtrace.Object{
	{Variable: ObjIpHdrOuter, HeaderFiles: headerFiles, StructDefs: []string{"iphdr"},
		Casts: map[string]string{
			"$skb": skb.NewDataCastBuilder("iphdr").SetOuterOffset(EthHdrLength).Build(),
		}},
}

var encapGreObj = []*skbtrace.Object{
	{Variable: ObjMplsHdrOuter, HeaderFiles: headerFiles, StructDefs: []string{"mplshdr"},
		SanityFilter: newTransportSanityFilter(ObjIpHdrOuter, GreProtocolNumber),
		Casts: map[string]string{
			"$skb": skb.NewDataCastBuilder("mplshdr").SetOuterOffset(
				EthHdrLength + IpHdrMinLength + GreHdrLength).Build(),
		}},
}

var encapUdpObj = []*skbtrace.Object{
	{Variable: ObjUdpHdrOuter, HeaderFiles: headerFiles, StructDefs: []string{"udphdr"},
		SanityFilter: newTransportSanityFilter(ObjIpHdrOuter, UdpProtocolNumber),
		Casts: map[string]string{
			"$skb": skb.NewDataCastBuilder("udphdr").SetOuterOffset(EthHdrLength + IpHdrMinLength).Build(),
		}},
	{Variable: ObjMplsHdrOuter, HeaderFiles: headerFiles, StructDefs: []string{"mplshdr"},
		SanityFilter: skbtrace.Filter{Object: ObjUdpHdrOuter, Field: "dest",
			Op: "==", Value: strconv.Itoa(MplsOverUdpPort)},
		Casts: map[string]string{
			"$skb": skb.NewDataCastBuilder("mplshdr").SetOuterOffset(
				EthHdrLength + IpHdrMinLength + UdpHdrLength).Build(),
		}},
}

//go:embed headers/mplshdr.h
var mplsHdrDef string

func convMplsLabel(obj, field string) ([]skbtrace.Statement, skbtrace.Expression) {
	// special logic for extracting label and applying ntohl to it:
	// network byte order:     [ L2   L1         L0,TC,S   TTL ]
	// (bit)                         24   20    16   12    8    4    0
	// host byte order (x86): 0x TTL  L0   TC,S  L1        L2
	//                                & 0xf00000 & 0xff00  & 0xff
	//                                | L0       | L1      | L2
	//                                | >> 20    | >> 4    | << 12
	//                                |     +--------------+
	//                                |     |    +----+
	//                                +-----|---------|----+
	//                                      |         |    |
	// label:                               L2        L1   L0
	// (bit)                         24   20    16   12    8    4    0
	stmts := []skbtrace.Statement{
		skbtrace.Stmtf("$mpls_label = %s", skbtrace.ExprField(obj, field)),
		skbtrace.Stmt("$mpls_label = ($mpls_label & 0xf00000) >> 20 | \n" +
			"   ($mpls_label & 0x00ff00) >> 4 | \n" +
			"   ($mpls_label & 0x0000ff) << 12"),
	}
	return stmts, skbtrace.Expr("$mpls_label")
}

func filtopMplsLabel(expr skbtrace.Expression, op, value string) (skbtrace.Expression, error) {
	if op != "==" {
		return skbtrace.NilExpr, errors.New("MPLS labels only support equality filters")
	}

	label, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return skbtrace.NilExpr, err
	}

	var bytes [4]byte
	skbtrace.HostEndian.PutUint32(bytes[:], uint32(label)<<4)
	return skbtrace.Exprf("(%s & 0xf0ffff) %s 0x%02x%02x%02x", expr, op,
		bytes[0], bytes[1], bytes[2]), nil
}

// Registers function used in inner header casts which picks difference between
// outer mac header pointer and first inner header pointer.
// Basically, this is a shortcut for longer overlay protochain option:
//   - gre (MPLSoGRE) - a single 4-byte gre header followed by a single MPLS label.
//   - udp (MPLSoUDP) - same as gre, but with 8-byte udp header.
func RegisterOverlayLengthFunc(b *skbtrace.Builder, encap string) {
	b.AddCastFunction(OverlayHeaderLengthFunc,
		func() (string, error) {
			switch encap {
			case EncapProtoUdp:
				return fmt.Sprint(BaseEncapHdrLength + UdpHdrLength + MplsHdrLength), nil
			case EncapProtoGre:
				return fmt.Sprint(BaseEncapHdrLength + GreHdrLength + MplsHdrLength), nil
			}
			return "", fmt.Errorf("invalid encapsulation type '%s'", encap)
		})
}

// An alternative for RegisterOverlayLengthFunc() which builds protochain internally.
// Can be used for mpls label stacking.
// NOTE: we should read at ($out_iph->ihl * 4), but do not want to impose extra dependency,
// so assume that we always have smallest possible ip header in overlay.
// FIXME: for now it doesn't affect outer header offsets in casts.
func RegisterOverlayLengthFuncProtoChain(b *skbtrace.Builder, protoChain []string) {
	b.AddCastFunction(OverlayHeaderLengthFunc,
		func() (string, error) {
			var offset int
			for _, proto := range protoChain {
				switch proto {
				case EncapProtoEth:
					offset += EthHdrLength
				case EncapProtoIp:
					offset += IpHdrMinLength
				case EncapProtoUdp:
					offset += UdpHdrLength
				case EncapProtoGre:
					offset += GreHdrLength
				case EncapProtoMpls:
					offset += MplsHdrLength
				default:
					return "", fmt.Errorf("invalid encapsulation protocol '%s'", proto)
				}
			}

			return strconv.Itoa(offset), nil
		})
}

func RegisterEncap(b *skbtrace.Builder, encap string) {
	b.AddFieldGroups(encapFieldGroups)
	b.AddFieldGroupTemplate(ipFieldGroup.Wrap(ObjIpHdrOuter, "outer"), ipRows)
	b.AddFieldGroupTemplate(udpFieldGroup.Wrap(ObjUdpHdrOuter, "outer"), udpRows)
	b.AddStructDef("mplshdr", mplsHdrDef)
	b.AddStructDef("iphdr", ipHdrDef)
	b.AddObjects(encapObj)

	switch encap {
	case EncapProtoGre:
		b.AddObjects(encapGreObj)
	case EncapProtoUdp:
		b.AddObjects(encapUdpObj)
	}
}
