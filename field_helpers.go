package skbtrace

import (
	"encoding/binary"
	"strconv"
	"strings"
)

func NewObjectConvExpr(format string) FieldConverter {
	return func(obj, field string) ([]Statement, Expression) {
		return nil, Exprf(format, obj)
	}
}

func NewConvBitfieldExpr(offset uint, mask uint64) FieldConverter {
	return func(obj, field string) ([]Statement, Expression) {
		return nil, Exprf(`(%s >> %d) & 0x%x`, ExprField(obj, field), offset, mask)
	}
}

// FormatVariableName formats intermediate variable name which can be used for nested fields
func FormatVariableName(field string) Expression {
	return Exprf("$%s", strings.ReplaceAll(strings.ReplaceAll(field, ".", "_"), "->", "_"))
}

// Generate simple converter for network byte order -- swap bytes in 16-bit word
func ConvNtohs(obj, field string) ([]Statement, Expression) {
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
func ConvNtohl(obj, field string) ([]Statement, Expression) {
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
