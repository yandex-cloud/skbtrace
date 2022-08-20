package proto

import (
	_ "embed"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/yandex-cloud/skbtrace"
	"github.com/yandex-cloud/skbtrace/pkg/skb"
)

const (
	ObjTcpHdr      = "$tcph"
	ObjTcpHdrInner = "$in_tcph"
	ObjUdpHdr      = "$udph"
	ObjUdpHdrInner = "$in_udph"

	TcpProtocolNumber = 6
	UdpProtocolNumber = 17
)

// TCP Flags
const (
	tcpFlagAck = 0x10
	tcpFlagPsh = 0x08
	tcpFlagRst = 0x04
	tcpFlagSyn = 0x02
	tcpFlagFin = 0x01

	tcpControlFlagMask = tcpFlagSyn | tcpFlagAck | tcpFlagRst | tcpFlagFin
)

type tcpFlag struct {
	chr byte
	val uint16
}

var tcpFlags = []tcpFlag{
	{'S', tcpFlagSyn},
	{'A', tcpFlagAck},
	{'P', tcpFlagPsh},
	{'F', tcpFlagFin},
	{'R', tcpFlagRst},
}

var transCommonFieldsRow = []*skbtrace.Field{
	{Name: "source", Alias: "sport", WeakAlias: true,
		Converter: skbtrace.ConvNtohs, Preprocessor: skbtrace.FppNtohs,
		Help: "Source port in TCP/UDP"},
	{Name: "dest", Alias: "dport", WeakAlias: true,
		Converter: skbtrace.ConvNtohs, Preprocessor: skbtrace.FppNtohs,
		Help: "Destination port in TCP/UDP"},
	{Name: "check", FmtSpec: "%x", Converter: skbtrace.ConvNtohs,
		Help: "Checksum in TCP/UDP"},
}

var udpFieldsRow = []*skbtrace.Field{
	{Name: "len", Converter: skbtrace.ConvNtohs,
		Help: "Length of UDP datagram"},
}

var tcpFieldsRow = []*skbtrace.Field{
	{Name: "seq", Alias: "seq", FmtSpec: "%lu", Converter: skbtrace.ConvNtohl,
		Help: "Absolute TCP Sequence Number"},
	{Name: "ack_seq", Alias: "ack", FmtSpec: "%lu", Converter: skbtrace.ConvNtohl,
		Help: "Absolute TCP Acknowledge Number"},
	{Name: "flags2_doff", FmtKey: "doff", Converter: convTcpDoff,
		Help: "TCP Data Offset in 32-bite words"},
	{Name: "window", FmtKey: "win", Converter: skbtrace.ConvNtohs,
		Help: "TCP Window Size"},
}

var tcpFlagsRow = []*skbtrace.Field{
	{Name: "flags1", FmtKey: "flags", Alias: "tcp-flags",
		FmtSpec:   strings.Repeat("%s", len(tcpFlags)),
		Converter: convTcpFlags, Preprocessor: fppTcpFlags, FilterOperator: filterOpTcpFlags,
		Help: "TCP Flags: S - SYN, A - ACK, P - PSH, F - FIN, R - RST"},
}

var udpRows = [][]*skbtrace.Field{append(transCommonFieldsRow, udpFieldsRow...)}
var tcpRows = [][]*skbtrace.Field{transCommonFieldsRow, tcpFieldsRow, tcpFlagsRow}
var udpFieldGroup = skbtrace.FieldGroup{Object: ObjUdpHdr, Row: "udp"}
var tcpFieldGroup = skbtrace.FieldGroup{Object: ObjTcpHdr, Row: "tcp"}

//go:embed headers/tcphdr.h
var tcpHdrDef string

//go:embed headers/udphdr.h
var udpHdrDef string

var headerFuncsTrans = []string{OverlayHeaderLengthFunc, InnerIpHeaderLengthFunc}
var objTrans = []*skbtrace.Object{
	{Variable: ObjTcpHdr, HeaderFiles: headerFiles, StructDefs: []string{"tcphdr"},
		SanityFilter: NewTransportSanityFilter(ObjIpHdr, TcpProtocolNumber),
		Casts: map[string]string{
			"$skb": skb.NewDataCastBuilder("tcphdr", "head").SetField("network_header").SetInnerHelpers(
				InnerIpHeaderLengthFunc).Build(),
		}},
	{Variable: ObjUdpHdr, HeaderFiles: headerFiles, StructDefs: []string{"udphdr"},
		SanityFilter: NewTransportSanityFilter(ObjIpHdr, UdpProtocolNumber),
		Casts: map[string]string{
			"$skb": skb.NewDataCastBuilder("udphdr", "head").SetField("network_header").SetInnerHelpers(
				InnerIpHeaderLengthFunc).Build(),
		}},
	{Variable: ObjTcpHdrInner, HeaderFiles: headerFiles, StructDefs: []string{"tcphdr"},
		SanityFilter: NewTransportSanityFilter(ObjIpHdrInner, TcpProtocolNumber),
		Casts: map[string]string{
			"$skb": skb.NewDataCastBuilder("tcphdr", "head").SetInnerHelpers(headerFuncsTrans...).Build(),
		}},
	{Variable: ObjUdpHdrInner, HeaderFiles: headerFiles, StructDefs: []string{"udphdr"},
		SanityFilter: NewTransportSanityFilter(ObjIpHdrInner, UdpProtocolNumber),
		Casts: map[string]string{
			"$skb": skb.NewDataCastBuilder("udphdr", "head").SetInnerHelpers(headerFuncsTrans...).Build(),
		}},
}

func NewTransportSanityFilter(obj string, protoNum int) skbtrace.Filter {
	return skbtrace.Filter{Object: obj, Field: "protocol", Op: "==", Value: strconv.Itoa(protoNum)}
}

func convTcpFlags(obj, field string) ([]skbtrace.Statement, skbtrace.Expression) {
	var flagExprs []skbtrace.Expression
	for _, flag := range tcpFlags {
		flagExprs = append(flagExprs,
			skbtrace.Exprf(`($tcp_flags & 0x%x) ? "%s" : "-"`, flag.val, []byte{flag.chr}))
	}

	stmts := []skbtrace.Statement{skbtrace.Stmtf("$tcp_flags = %s", skbtrace.ExprField(obj, field))}
	return stmts, skbtrace.ExprJoin(flagExprs)
}

func convTcpDoff(obj, field string) ([]skbtrace.Statement, skbtrace.Expression) {
	return nil, skbtrace.Exprf("(%s >> 4)", skbtrace.ExprField(obj, field))
}

func fppTcpFlags(op, value string) (string, error) {
	if op != "==" {
		return "", fmt.Errorf("TCP control flags may be compared only for equality")
	}

	var mask uint16
	for _, chr := range []byte(value) {
		var chrMask uint16
		for _, flag := range tcpFlags {
			if flag.chr == chr {
				if flag.val&tcpControlFlagMask == 0 {
					return "", errors.New("only TCP control flags can be used in filters")
				}

				chrMask = flag.val
				break
			}
		}
		if chrMask == 0 {
			return "", fmt.Errorf("unknown TCP flag mnemonic '%c'", rune(chr))
		}
		mask |= chrMask
	}
	return fmt.Sprintf("0x%x", mask), nil
}

func filterOpTcpFlags(expr skbtrace.Expression, op, value string) (skbtrace.Expression, error) {
	return skbtrace.Exprf("(%s & 0x%x) %s %s", expr, tcpControlFlagMask, op, value), nil
}

func prepareTransportObjects(isIPv6 bool) {
	for _, obj := range objTrans {
		switch obj.Variable {
		case ObjTcpHdr, ObjUdpHdr:
			if isIPv6 {
				obj.SanityFilter.Object = ObjIpv6Hdr
				obj.SanityFilter.Field = "nexthdr"
			} else {
				obj.SanityFilter.Object = ObjIpHdr
				obj.SanityFilter.Field = "protocol"
			}
		case ObjUdpHdrInner, ObjTcpHdrInner:
			if isIPv6 {
				obj.SanityFilter.Object = ObjIpv6HdrInner
				obj.SanityFilter.Field = "nexthdr"
			} else {
				obj.SanityFilter.Object = ObjIpHdrInner
				obj.SanityFilter.Field = "protocol"
			}
		}
	}
}

func RegisterTransport(b *skbtrace.Builder, isIPv6 bool) {
	b.AddFieldGroupTemplate(udpFieldGroup, udpRows)
	b.AddFieldGroupTemplate(udpFieldGroup.Wrap(ObjUdpHdrInner, "inner"), udpRows)
	b.AddFieldGroupTemplate(tcpFieldGroup, tcpRows)
	b.AddFieldGroupTemplate(tcpFieldGroup.Wrap(ObjTcpHdrInner, "inner"), tcpRows)

	prepareTransportObjects(isIPv6)
	b.AddObjects(objTrans)

	b.AddStructDef("tcphdr", tcpHdrDef)
	b.AddStructDef("udphdr", udpHdrDef)
}
