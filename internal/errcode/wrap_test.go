package errcode_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A coded sentinel wrapped first by fmt.Errorf ("%w: detail") shows only its
// message on screen, because Render prints typed parts and not a wrapper's
// words: such a site uses errcode.With. The check reads every non-test Go
// file of the module and knows a sentinel as a package-level variable
// initialized with errcode.New, or a direct errcode.New call.
func TestNoSentinelFirstWraps(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	type file struct {
		dir string
		f   *ast.File
	}
	var files []file
	// sentinels holds "<dir>.<name>" of every coded sentinel variable.
	sentinels := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name != "." && name != ".." && (strings.HasPrefix(name, ".") || name == "testdata" || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		dir := filepath.ToSlash(filepath.Dir(path))
		files = append(files, file{dir, f})
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, v := range vs.Values {
					if isErrcodeNew(v) && i < len(vs.Names) {
						sentinels[dir+"."+vs.Names[i].Name] = true
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	module := modulePath(t, root)
	for _, fl := range files {
		imports := map[string]string{}
		for _, im := range fl.f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			rel, ok := strings.CutPrefix(p, module+"/")
			if !ok {
				continue
			}
			name := filepath.Base(rel)
			if im.Name != nil {
				name = im.Name.Name
			}
			imports[name] = filepath.ToSlash(filepath.Join(root, rel))
		}
		ast.Inspect(fl.f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 || !isSelector(call.Fun, "fmt", "Errorf") {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			format, _ := strconv.Unquote(lit.Value)
			if !strings.HasPrefix(format, "%w") {
				return true
			}
			first := call.Args[1]
			coded := isErrcodeNew(first)
			switch e := first.(type) {
			case *ast.Ident:
				coded = coded || sentinels[fl.dir+"."+e.Name]
			case *ast.SelectorExpr:
				if pkg, ok := e.X.(*ast.Ident); ok {
					coded = coded || sentinels[imports[pkg.Name]+"."+e.Sel.Name]
				}
			}
			if coded {
				t.Errorf("%s: fmt.Errorf(%q, <coded sentinel>, ...): use errcode.With so the detail reaches the user", fset.Position(call.Pos()), format)
			}
			return true
		})
	}
}

func isSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg && sel.Sel.Name == name
}

// isErrcodeNew reports whether e is errcode.New(...), or New(...) inside
// package errcode.
func isErrcodeNew(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	return ok && isSelector(call.Fun, "errcode", "New")
}

func modulePath(t *testing.T, root string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.Lines(string(b)) {
		if m, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(m)
		}
	}
	t.Fatal("go.mod names no module")
	return ""
}
