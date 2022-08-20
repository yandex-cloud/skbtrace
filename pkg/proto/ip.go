package proto

import (
	_ "embed"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"

	"github.com/yandex-cloud/skbtrace"
	"github.com/yandex-cloud/skbtrace/pkg/skb"
)

const (
	ObjIpHdr      = "$iph"
	ObjIpHdrInner = "$in_iph"

	ObjIpv6Hdr      = "$ipv6h"
	ObjIpv6HdrInner = "$in_ipv6h"

	InnerIpHeaderLengthFunc = "InnerIpHeaderLength"
	IpHdrMinLength          = 20
	Ipv6HdrMinLength        = 40
)

const ipAddressNote = "Dotted form used both for formatting and as filter values."

var ipFieldsRow1 = []*skbtrace.Field{
	{Name: "ihl_version", FmtKey: "ihl/ver", FmtSpec: "%x",
		SanityFilter: &skbtrace.Filter{Op: "==", Value: "0x45"}},
	{Name: "tot_len", Alias: "iplen", Converter: skbtrace.ConvNtohs,
		Help: "Total length of IP packet in bytes"},
	{Name: "frag_off", FmtSpec: "%d (%s %s)", Converter: convFragOff,
		Help: "Fragment offset in bytes, MF (More Fragments) and DF (Do no Fragment) flags."},
	{Name: "check", FmtSpec: "%x", Converter: skbtrace.ConvNtohs},
}
var ipFieldsRow2 = []*skbtrace.Field{
	{Name: "id", Alias: "id", FmtSpec: "%d", Converter: skbtrace.ConvNtohs},
	{Name: "ttl",
		Help: "IP Time To Live"},
	{Name: "protocol",
		Help: "IP Protocol Number as decimal (6 - TCP, 17 - UDP, 1 - ICMP)"},
	{Name: "saddr", Alias: "src", WeakAlias: true, FmtSpec: "%s",
		Converter: ConvNtopInet, Preprocessor: FppPtonInet,
		Help: "Source IP Address. " + ipAddressNote},
	{Name: "daddr", Alias: "dst", WeakAlias: true, FmtSpec: "%s",
		Converter: ConvNtopInet, Preprocessor: FppPtonInet,
		Help: "Destination IP Address. " + ipAddressNote},
}

var ipv6FieldRow1 = []*skbtrace.Field{
	{Name: "priority_version", FmtSpec: "%x",
		SanityFilter: &skbtrace.Filter{Op: "&", Value: "0x60"}},
	{Name: "flow_lbl", Alias: "id", FmtSpec: "%d", Converter: convIpv6FlowLabel,
		ConverterMask: skbtrace.ConverterDump | skbtrace.ConverterHiddenKey | skbtrace.ConverterFilter},
	{Name: "payload_len", Alias: "iplen", Converter: skbtrace.ConvNtohs, Preprocessor: skbtrace.FppNtohs},
}
var ipv6FieldRow2 = []*skbtrace.Field{
	{Name: "nexthdr"},
	{Name: "hop_limit"},
	{Name: "saddr8", Alias: "src", WeakAlias: true, FmtKey: "src", FmtSpec: "%s",
		Converter: ConvNtopInet6, ConverterMask: skbtrace.ConverterDump | skbtrace.ConverterHiddenKey,
		FilterOperator: FiltopPtonInet6, Help: "Source IP Address. " + ipAddressNote},
	{Name: "daddr8", Alias: "dst", WeakAlias: true, FmtKey: "dst", FmtSpec: "%s",
		Converter: ConvNtopInet6, ConverterMask: skbtrace.ConverterDump | skbtrace.ConverterHiddenKey,
		FilterOperator: FiltopPtonInet6, Help: "Destination IP Address. " + ipAddressNote},
}

var ipRows = [][]*skbtrace.Field{ipFieldsRow1, ipFieldsRow2}
var ipFieldGroup = skbtrace.FieldGroup{Object: ObjIpHdr, Row: "ip"}

var ipv6Rows = [][]*skbtrace.Field{ipv6FieldRow1, ipv6FieldRow2}
var ipv6FieldGroup = skbtrace.FieldGroup{Object: ObjIpv6Hdr, Row: "ipv6"}

//go:embed headers/iphdr.h
var ipHdrDef string

//go:embed headers/ipv6hdr.h
var ipv6HdrDef string

type InvalidIPv4AddressError struct {
	Address string
	IsIPv6  bool
}

func (e *InvalidIPv4AddressError) Error() string {
	return fmt.Sprintf("invalid IPv4 address '%s'", e.Address)
}

var objIp = []*skbtrace.Object{
	{Variable: ObjIpHdr, HeaderFiles: headerFiles, StructDefs: []string{"iphdr"},
		Casts: map[string]string{
			"$skb": skb.NewDataCastBuilder("iphdr", "head").SetField("network_header").Build(),
		}},
	{Variable: ObjIpHdrInner, HeaderFiles: headerFiles, StructDefs: []string{"iphdr"},
		Casts: map[string]string{
			"$skb": skb.NewDataCastBuilder("iphdr", "head").SetInnerHelpers(OverlayHeaderLengthFunc).Build(),
		}},
}

var objIpv6 = []*skbtrace.Object{
	{Variable: ObjIpv6Hdr, HeaderFiles: headerFiles, StructDefs: []string{"ipv6hdr"},
		Casts: map[string]string{
			"$skb": skb.NewDataCastBuilder("ipv6hdr", "head").SetField("network_header").Build(),
		}},
	{Variable: ObjIpv6HdrInner, HeaderFiles: headerFiles, StructDefs: []string{"ipv6hdr"},
		Casts: map[string]string{
			"$skb": skb.NewDataCastBuilder("ipv6hdr", "head").SetInnerHelpers(OverlayHeaderLengthFunc).Build(),
		}},
}

func convNtop(af int, obj, field string) ([]skbtrace.Statement, skbtrace.Expression) {
	return nil, skbtrace.Exprf("ntop(%d, %s->%s)", af, obj, field)
}

func ConvNtopInet(obj, field string) ([]skbtrace.Statement, skbtrace.Expression) {
	return convNtop(syscall.AF_INET, obj, field)
}

func ConvNtopInet6(obj, field string) ([]skbtrace.Statement, skbtrace.Expression) {
	return convNtop(syscall.AF_INET6, obj, field)
}

func convIpv6FlowLabel(obj, field string) ([]skbtrace.Statement, skbtrace.Expression) {
	stmts := []skbtrace.Statement{
		skbtrace.Stmtf("$flow_label = (%[1]s[0] & 0x0f) << 16 | \n"+
			"   %[1]s[1] << 8 | %[1]s[2]",
			skbtrace.ExprField(obj, field)),
	}
	return stmts, skbtrace.Expr("$flow_label")
}

func FppPtonInet(op, value string) (string, error) {
	if op != "==" {
		return "", fmt.Errorf("IP addresses can be compared only with equals")
	}

	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return "", &InvalidIPv4AddressError{Address: value, IsIPv6: ip != nil}
	}

	u := skbtrace.HostEndian.Uint32(ip.To4())
	return fmt.Sprintf("0x%x", u), nil
}

func FiltopPtonInet6(expr skbtrace.Expression, op, value string) (skbtrace.Expression, error) {
	if op != "==" {
		return skbtrace.NilExpr, fmt.Errorf("IP addresses can be compared only with equals")
	}

	ip := net.ParseIP(value)
	if ip == nil {
		return skbtrace.NilExpr, fmt.Errorf("invalid IPv6 address '%s'", value)
	}

	// It seems that bpftrace 0.9.2 misinterprets uint64 literals so fallback to 32-bit
	// (yc-bpf-trace had 64-bit counters, but probably broken too)
	addrField := string(expr)
	if strings.HasSuffix(string(expr), "8") {
		addrField = addrField[:len(addrField)-1] + "32"
	}

	var exprs []skbtrace.Expression
	for i := 0; i < 4; i++ {
		u := skbtrace.HostEndian.Uint32(ip[i*4 : i*4+4])
		exprs = append(exprs, skbtrace.Exprf("%s[%d] == 0x%x", addrField, i, u))
	}

	return skbtrace.ExprJoinOp(exprs, "&&"), nil
}

func convFragOff(obj string, field string) ([]skbtrace.Statement, skbtrace.Expression) {
	stmts, expr := skbtrace.ConvNtohs(obj, field)
	vars := []string{
		fmt.Sprintf("(%s & 0x1fff) * 8", expr),
		fmt.Sprintf(`(%s & 0x2000) ? "MF" : "-"`, expr),
		fmt.Sprintf(`(%s & 0x4000) ? "DF" : "-"`, expr),
	}

	return stmts, skbtrace.Expression(strings.Join(vars, ", "))
}

func RegisterInnerIpLengthFunc(b *skbtrace.Builder, isIPv6 bool) {
	b.AddCastFunction(InnerIpHeaderLengthFunc,
		func() (string, error) {
			// NOTE: This assumes that no IP options are present
			if isIPv6 {
				return strconv.Itoa(Ipv6HdrMinLength), nil
			}

			return strconv.Itoa(IpHdrMinLength), nil
		})
}

func RegisterIp(b *skbtrace.Builder, isIPv6 bool) {
	if isIPv6 {
		b.AddFieldGroupTemplate(ipv6FieldGroup, ipv6Rows)
		b.AddFieldGroupTemplate(ipv6FieldGroup.Wrap(ObjIpv6HdrInner, "inner"), ipv6Rows)
		b.AddObjects(objIpv6)
		b.AddStructDef("ipv6hdr", ipv6HdrDef)
	} else {
		b.AddFieldGroupTemplate(ipFieldGroup, ipRows)
		b.AddFieldGroupTemplate(ipFieldGroup.Wrap(ObjIpHdrInner, "inner"), ipRows)
		b.AddObjects(objIp)
		b.AddStructDef("iphdr", ipHdrDef)
	}
}
