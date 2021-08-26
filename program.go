package skbtrace

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	programIndent = "    "
)

type AggrFunc string

const (
	AFCount AggrFunc = "count"
	AFSum   AggrFunc = "sum"
	AFAvg   AggrFunc = "avg"
	AFMin   AggrFunc = "min"
	AFMax   AggrFunc = "max"
	AFHist  AggrFunc = "hist"
)

var AggrFuncList = []AggrFunc{AFCount, AFSum, AFAvg, AFMin, AFMax, AFHist}

type Statement struct {
	s string
	b *Block
}

type Expression string

// Empty expression used as default value in conjuction with error
var NilExpr = Expr("")

type BlockContext map[string]struct{}

// Block is an internal representation for BPFTrace block which stores list of semicolon
// separated statements.
//
// Probe block contains list of BPFTrace statements (and other blocks) to be executed by probe
// Context is a dictionary which maps objects to local variables produced by casts
// or predefined variables passed into probe
type Block struct {
	Preamble   string
	Statements []Statement

	prog  *Program
	probe *Probe

	context BlockContext
}

type Program struct {
	HeaderFiles map[string]struct{}
	StructDefs  map[string]*StructDef
	Blocks      []*Block
}

func NewProgram() *Program {
	return &Program{
		HeaderFiles: make(map[string]struct{}),
		StructDefs:  make(map[string]*StructDef),
	}
}

func (prog *Program) render(w io.Writer, initialIndent bool) error {
	buf := bufio.NewWriter(w)

	indent := ""
	if initialIndent {
		indent = programIndent
	}

	writeSep := func() {}
	writeSep1 := func() { buf.WriteString("\n") }
	writeSep2 := func() { buf.WriteString("\n\n") }

	for headerFile := range prog.HeaderFiles {
		buf.WriteString(indent)
		buf.WriteString(fmt.Sprintf("#include <%s>\n", headerFile))
		writeSep = writeSep1
	}

	for _, structDef := range prog.StructDefs {
		writeSep()
		structDef.render(buf, indent)
		writeSep = writeSep2
	}

	for _, block := range prog.Blocks {
		writeSep()
		block.render(buf, indent)
		writeSep = writeSep2
	}

	return buf.Flush()
}

func (structDef *StructDef) render(buf *bufio.Writer, indent string) {
	buf.WriteString(indent)
	buf.WriteString(fmt.Sprintf("struct %s {\n", structDef.TypeName))

	lineIndent := indent + programIndent
	for _, line := range structDef.Text {
		if len(line) == 0 {
			continue
		}

		buf.WriteString(lineIndent)
		buf.WriteString(line)
		buf.WriteByte('\n')
	}

	buf.WriteString(indent)
	buf.WriteByte('}')
}

func (block *Block) render(buf *bufio.Writer, indent string) {
	buf.WriteString(indent)
	if len(block.Preamble) > 0 {
		buf.WriteString(block.Preamble)
		buf.WriteByte(' ')
	}
	buf.WriteString("{\n")

	blockIndent := indent + programIndent
	for _, stmt := range block.Statements {
		if stmt.b != nil {
			stmt.b.render(buf, blockIndent)
			buf.WriteByte('\n')
			continue
		}

		lines := []string{stmt.s}
		if strings.IndexByte(stmt.s, '\n') > 0 {
			lines = strings.Split(stmt.s, "\n")
		}
		for i, line := range lines {
			if i > 0 {
				buf.WriteByte('\n')
			}
			buf.WriteString(blockIndent)
			buf.WriteString(line)
		}
		buf.WriteString(";\n")

	}

	buf.WriteString(indent)
	buf.WriteByte('}')
}

func (prog *Program) AddProbeBlock(probeDef string, probe *Probe) *Block {
	block := &Block{
		Preamble: probeDef,
		probe:    probe,
		prog:     prog,
		context:  make(BlockContext),
	}

	prog.Blocks = append(prog.Blocks, block)
	return block
}

func (prog *Program) AddIntervalBlock(d time.Duration) *Block {
	if d.Seconds() > 0 {
		return prog.AddProbeBlock(fmt.Sprintf("interval:s:%d", int(d.Seconds())), nil)
	}

	return prog.AddProbeBlock(fmt.Sprintf("interval:ms:%d", int(d.Milliseconds())), nil)
}

func (prog *Program) AddIntervalOrEndBlock(d time.Duration) *Block {
	block := prog.AddIntervalBlock(d)
	block.Preamble = fmt.Sprintf("%s, END", block.Preamble)
	return block
}

func (prog *Program) addCommonBlock(opt *CommonOptions) {
	timeoutBlock := prog.AddIntervalBlock(opt.Timeout)
	timeoutBlock.Add(Stmt("exit()"))
}

func (prog *Program) addAggrDumpBlock(interval time.Duration) {
	block := prog.AddIntervalBlock(interval)
	block.Add(
		Stmt("time()"),
		Stmt("print(@)"),
		Stmt("clear(@)"))
}

func (prog *Program) addAggrCleanupBlock(aggrs ...string) {
	// Cleanup start_time map in case it will leak
	block := prog.AddIntervalOrEndBlock(aggrCleanupInterval)
	for _, aggr := range aggrs {
		block.Addf("clear(%s)", aggr)
	}
}

// Add adds single-string statements to the block
func (block *Block) Add(stmts ...Statement) {
	block.Statements = append(block.Statements, stmts...)
}

// Addf formats a single-string statement and adds it to the list of block statements
func (block *Block) Addf(format string, args ...interface{}) {
	block.Statements = append(block.Statements, Stmtf(format, args...))
}

// AddBlock adds block statement
func (block *Block) AddBlock(preamble string) *Block {
	block2 := &Block{
		Preamble: preamble,
		probe:    block.probe,
		prog:     block.prog,
		context:  make(BlockContext),
	}

	for k, v := range block.context {
		block2.context[k] = v
	}

	block.Statements = append(block.Statements, Statement{b: block2})
	return block2
}

// AddIfBlock adds block statement with if preamble containing conditions
func (block *Block) AddIfBlock(conds ...Expression) *Block {
	return block.AddBlock(fmt.Sprintf("if (%s)", ExprJoinOp(conds, "&&")))
}

// Finds a block which already have object fetched, converted and sanity filters
// applied (minor deduplication of casts)
func (block *Block) findBlockWithObject(objName string) *Block {
	if _, ok := block.context[objName]; ok {
		return block
	}

	for _, stmt := range block.Statements {
		if stmt.b == nil {
			continue
		}

		b2 := stmt.b.findBlockWithObject(objName)
		if b2 != nil {
			return b2
		}
	}

	return nil
}

// Stmt creates a new statement that consists from single string
func Stmt(s string) Statement {
	return Statement{s: s}
}

// Stmtf creates a formats a single-string statement using a format string and its argument
func Stmtf(format string, args ...interface{}) Statement {
	return Statement{s: fmt.Sprintf(format, args...)}
}

// Wraps block into statement
func stmtBlock(block *Block) Statement {
	return Statement{b: block}
}

// Expr converts a string to expression
func Expr(e string) Expression {
	return Expression(e)
}

// Exprf formats an expression
func Exprf(format string, args ...interface{}) Expression {
	return Expression(fmt.Sprintf(format, args...))
}

// ExprField formats an expression for accessing the field
func ExprField(obj, field string) Expression {
	// Some fields do not have objects (like raw arguments with values)
	if len(obj) == 0 {
		return Expr(field)
	}
	if len(field) == 0 {
		return Expr(obj)
	}

	return Exprf("%s->%s", obj, field)
}

// ExprJoin joins expressions as list separated by comma
func ExprJoin(exprs []Expression) Expression {
	return exprJoin(exprs, "", ",", " ")
}

// ExprJoinOp joins expressions using operator op
func ExprJoinOp(exprs []Expression, op string) Expression {
	return exprJoin(exprs, " ", op, " ")
}

func exprJoin(exprs []Expression, pre, sep, post string) Expression {
	buf := bytes.NewBuffer(nil)
	for i, expr := range exprs {
		if i > 0 {
			buf.WriteString(pre)
			buf.WriteString(sep)
			buf.WriteString(post)
		}

		buf.WriteString(string(expr))
	}
	return Expr(buf.String())
}
