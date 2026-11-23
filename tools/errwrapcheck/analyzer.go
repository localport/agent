package main

import (
	"go/ast"
	"go/constant"
	"go/types"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const errcodePath = "github.com/localport/agent/internal/errcode"

// Analyzer reports fmt.Errorf and errcode Invalid constructor calls that
// wrap a coded error, an operand of static type *errcode.Error, with other
// format text. errcode.Render prints typed parts only, so that text never
// reaches the user: such a site passes the text to (*errcode.Error).With or
// errcode.WithRemedy. An Invalid built "<prefix>: %w" is exempt: Render
// prints its prefix. Test files are not checked.
var Analyzer = &analysis.Analyzer{
	Name:     "errwrapcheck",
	Doc:      "report fmt.Errorf and errcode Invalid constructor text around a coded error, which errcode.Render does not print",
	URL:      "https://github.com/localport/agent/blob/main/docs/ERRORS.md",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
	ins := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	ins.Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node) {
		call := n.(*ast.CallExpr)
		kind := errorfKind(pass.TypesInfo, call)
		if len(call.Args) < 2 || kind == notErrorf {
			return
		}
		if strings.HasSuffix(pass.Fset.Position(call.Pos()).Filename, "_test.go") {
			return
		}
		tv, ok := pass.TypesInfo.Types[call.Args[0]]
		if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
			return
		}
		format := constant.StringVal(tv.Value)
		if format == "%w" {
			return
		}
		if head, ok := strings.CutSuffix(format, ": %w"); kind == invalidf && ok && !strings.Contains(head, "%w") {
			return
		}
		operands, ok := wrapOperands(format)
		if !ok {
			return
		}
		for _, i := range operands {
			if i+1 >= len(call.Args) {
				continue
			}
			arg := call.Args[i+1]
			if isCodedError(pass.TypesInfo.TypeOf(arg)) {
				pass.ReportRangef(arg, "format text around a coded error is not shown to the user; use (*errcode.Error).With or errcode.WithRemedy")
			}
		}
	})
	return nil, nil
}

type errorf int

const (
	notErrorf errorf = iota
	fmtErrorf
	// invalidf is an errcode Invalid constructor, which formats as fmt.Errorf.
	invalidf
)

// errorfKind reports whether call is fmt.Errorf or an errcode Invalid constructor.
func errorfKind(info *types.Info, call *ast.CallExpr) errorf {
	var id *ast.Ident
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		id = fun.Sel
	case *ast.Ident:
		id = fun
	default:
		return notErrorf
	}
	fn, ok := info.Uses[id].(*types.Func)
	if !ok || fn.Pkg() == nil {
		return notErrorf
	}
	switch path, name := fn.Pkg().Path(), fn.Name(); {
	case path == "fmt" && name == "Errorf":
		return fmtErrorf
	case path == errcodePath && (name == "InvalidArgf" || name == "InvalidConfigf" || name == "Unsupportedf"):
		return invalidf
	}
	return notErrorf
}

func isCodedError(t types.Type) bool {
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj.Pkg() != nil && obj.Pkg().Path() == errcodePath && obj.Name() == "Error"
}

// wrapOperands returns the operand indexes, counted from the first argument
// after the format, of the %w verbs in format, following fmt's rules for
// flags, width, precision, '*' and explicit [n] indexes. ok is false for a
// malformed index, which the printf vet check reports.
func wrapOperands(format string) (operands []int, ok bool) {
	arg := 0
	i := 0
	index := func() bool {
		if i >= len(format) || format[i] != '[' {
			return true
		}
		end := strings.IndexByte(format[i:], ']')
		if end < 0 {
			return false
		}
		n, err := strconv.Atoi(format[i+1 : i+end])
		if err != nil || n < 1 {
			return false
		}
		arg = n - 1
		i += end + 1
		return true
	}
	number := func() {
		if i < len(format) && format[i] == '*' {
			arg++
			i++
			return
		}
		for i < len(format) && format[i] >= '0' && format[i] <= '9' {
			i++
		}
	}
	for i < len(format) {
		if format[i] != '%' {
			i++
			continue
		}
		i++
		for i < len(format) && strings.IndexByte("+-# 0", format[i]) >= 0 {
			i++
		}
		if !index() {
			return nil, false
		}
		number()
		if i < len(format) && format[i] == '.' {
			i++
			if !index() {
				return nil, false
			}
			number()
		}
		if !index() {
			return nil, false
		}
		if i >= len(format) {
			break
		}
		verb := format[i]
		i++
		if verb == '%' {
			continue
		}
		if verb == 'w' {
			operands = append(operands, arg)
		}
		arg++
	}
	return operands, true
}
