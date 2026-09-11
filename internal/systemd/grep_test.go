package systemd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionSourceGuards(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := entry.Name()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for lineNo, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, `"sh"`) || strings.Contains(line, `"bash"`) {
				t.Errorf("%s:%d contains shell executable literal", path, lineNo+1)
			}
		}
		file, err := parser.ParseFile(fset, path, data, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && isTestOnlySeam(id.Name) {
						t.Errorf("%s:%d reassigns test-only seam %q", path, fset.Position(id.Pos()).Line, id.Name)
					}
				}
			case *ast.GoStmt:
				t.Errorf("%s:%d contains goroutine creation", path, fset.Position(n.Go).Line)
			}
			return true
		})
	}
}

func isTestOnlySeam(name string) bool {
	switch name {
	case "unitDir", "wantsDir", "stateDir", "logDir", "dataDir", "binaryPrefix", "unitsBackupDir", "nowUnixNano", "waitPollInterval", "rootCheck":
		return true
	default:
		return false
	}
}

func TestProductionSourceHasNoSecretMarker(t *testing.T) {
	entries, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range entries {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), secretMarker) {
			t.Fatalf("%s contains test secret marker", path)
		}
	}
}
