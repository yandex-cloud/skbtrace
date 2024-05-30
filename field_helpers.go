package skbtrace

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

type BuiltinType string

const (
	TBool   BuiltinType = "bool"
	TInt8   BuiltinType = "int8"
	TInt16  BuiltinType = "int16"
	TInt32  BuiltinType = "int32"
	TInt64  BuiltinType = "int64"
	TUInt8  BuiltinType = "uint8"
	TUInt16 BuiltinType = "uint16"
	TUInt32 BuiltinType = "uint32"
	TUInt64 BuiltinType = "uint64"
)

var FeatureBSwapFunction = &Feature{
	Component: FeatureComponentBPFTrace,
	Name:      "bswap",
	Help:      "Allows to use bswap in byte-swapping operations",

	Commit:     "1972e897da6ecb060a6e114e25dd1577e41dee47",
	MinVersion: Version{Major: 0, Submajor: 15, Minor: 0},
}

var FeatureBuiltinTypes = &Feature{
	Component: FeatureComponentBPFTrace,
	Name:      "builtin_type",
	Help:      "Allows to use builtin type conversions",

	Commit:     "5dd033c7c76dbe2557a64c204b336e65712c1ce8",
	MinVersion: Version{Major: 0, Submajor: 17, Minor: 0},
}

func NewObjectConvExpr(format string) FieldConverter {
	return func(obj, field string) ([]Statement, Expression) {
		return nil, Exprf(format, obj)
	}
}

func NewObjectBinOpConvExpr(left, right string, binOp string, convType BuiltinType, mask FeatureFlagMask) FieldConverter {
	if convType != "" {
		if mask.Supports(FeatureBuiltinTypes) {
			left = fmt.Sprintf("(%s)%s", convType, left)
			right = fmt.Sprintf("(%s)%s", convType, right)
		}
	}

	return func(obj, field string) ([]Statement, Expression) {
		return nil, Exprf(left+binOp+right, obj)
	}
}

func NewConvBitfieldExpr(offset uint, mask uint64) FieldConverter {
	return func(obj, field string) ([]Statement, Expression) {
		return nil, Exprf(`(%s >> %d) & 0x%x`, ExprField(obj, field), offset, mask)
	}
}

func NewArrayConvExpr(size int) FieldConverter {
	return func(obj, field string) ([]Statement, Expression) {
		fieldExpr := ExprField(obj, field)
		exprs := make([]Expression, size)
		for i := range exprs {
			exprs[i] = Exprf(`%s[%d]`, fieldExpr, i)
		}
		return nil, ExprJoin(exprs)
	}
}

func NewArrayConvFmtSpec(size int, fmtkey string) string {
	s := strings.Repeat(fmtkey+", ", size)
	return s[:len(s)-2]
}

// FormatVariableName formats intermediate variable name which can be used for nested fields
func FormatVariableName(field string) Expression {
	return Exprf("$%s", strings.ReplaceAll(strings.ReplaceAll(field, ".", "_"), "->", "_"))
}

// Generate simple converter for network byte order -- swap bytes in 16-bit word
func convNtohs(obj, field string) ([]Statement, Expression) {
	varName := FormatVariableName(field)
	stmts := []Statement{
		Stmtf("%s = %s->%s", varName, obj, field),
		Stmtf("%[1]s = (%[1]s >> 8) | ((%[1]s & 0xff) << 8)", varName),
	}

	return stmts, varName
}

// Field preprocessor for ntohs values
func FppNtohs(op, value string) (string, error) {
	base := 10
	if len(value) > 2 && value[:2] == "0x" {
		value = value[2:]
		base = 16
	}

	uintValue, err := strconv.ParseUint(value, base, 16)
	if err != nil {
		return "", err
	}

	var bytes [2]byte
	HostEndian.PutUint16(bytes[:], uint16(uintValue))
	netValue := binary.BigEndian.Uint16(bytes[:])

	return strconv.FormatUint(uint64(netValue), 10), nil
}

// Generate simple converter for network byte order -- swap bytes in 32-bit word
func convNtohl(obj, field string) ([]Statement, Expression) {
	varName := FormatVariableName(field)
	stmts := []Statement{
		Stmtf("%s = %s->%s", varName, obj, field),
		Stmtf("%[1]s = (%[1]s >> 24) | \n"+
			"           ((%[1]s & 0x00ff0000) >> 8) | \n"+
			"           ((%[1]s & 0x0000ff00) << 8) | \n"+
			"           ((%[1]s & 0x000000ff) << 24)", varName),
	}

	return stmts, varName
}

func convBSwap(obj, field string) ([]Statement, Expression) {
	return nil, Exprf("bswap(%s->%s)", obj, field)
}

func convBSwap16(obj, field string) ([]Statement, Expression) {
	return nil, Exprf("bswap((uint16)%s->%s)", obj, field)
}

func convBSwap32(obj, field string) ([]Statement, Expression) {
	return nil, Exprf("bswap((uint32)%s->%s)", obj, field)
}

func NewBSwapConv(featureMask FeatureFlagMask, bitSize uint) FieldConverter {
	if featureMask.Supports(FeatureBSwapFunction) {
		if featureMask.Supports(FeatureBuiltinTypes) {
			switch bitSize {
			case 16:
				return convBSwap16
			case 32:
				return convBSwap32
			}
		} else {
			return convBSwap
		}
	} else {
		switch bitSize {
		case 16:
			return convNtohs
		case 32:
			return convNtohl
		}
	}

	panic(fmt.Errorf("bitSize = %d is not supported by bswap-converters", bitSize))
}

func init() {
	RegisterFeatures(FeatureBSwapFunction, FeatureBuiltinTypes)
}
