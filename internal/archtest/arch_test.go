// Package archtest enforces the product/deployment architecture boundary
// (architecture doc, section 2.2, invariant 1): the authoritative tunnel
// engine (pkg/*) must never depend on deployment/orchestration packages.
//
// Pre-existing allowed exception: internal/testutil (the in-memory
// transport test helper, Phase 1) is a TEST helper imported only by
// pkg/* _test.go files; it is not deployment orchestration. It is
// allowlisted so the rule stays meaningful: any NEW internal package
// imported by pkg/* fails the gate.
//
// The rule is directional:
//
//	cmd/*  may import internal/* (thin transport wrappers over the engine)
//	pkg/*  may NOT import internal/* (the engine is the foundation)
//
// The check is AST-based (parses imports only) and runs in CI on every
// PR, so a boundary regression fails the build gate, not a review.
package archtest

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const modulePath = "github.com/Zaltapar/iran-germany-split-tunnel"

// allowedInternal lists the pre-existing internal packages that pkg/*
// may import (test helpers only). Anything else is a boundary violation.
var allowedInternal = map[string]bool{
	modulePath + "/internal/testutil": true,
}

// TestPkgNeverImportsInternal asserts that no .go file under pkg/ (test or
// otherwise) imports an internal/ package of this module, except the
// allowlisted pre-existing test helper.
func TestPkgNeverImportsInternal(t *testing.T) {
	root := moduleRoot(t)
	pkgDir := filepath.Join(root, "pkg")
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatalf("reading pkg/: %v", err)
	}

	fset := token.NewFileSet()
	violations := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub := filepath.Join(pkgDir, e.Name())
		files, err := filepath.Glob(filepath.Join(sub, "*.go"))
		if err != nil {
			t.Fatalf("globbing %s: %v", sub, err)
		}
		for _, f := range files {
			ast, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parsing %s: %v", f, err)
			}
			for _, imp := range ast.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if isBoundaryViolation(path) {
					violations++
					t.Errorf("boundary violation: pkg/%s imports %s — the tunnel engine (pkg/*) must not depend on deployment/orchestration packages (allowlist: %v)", e.Name(), path, allowlistNames())
				}
			}
		}
	}
	if violations > 0 {
		t.Fatalf("%d boundary violation(s); see errors above", violations)
	}
}

func allowlistNames() []string {
	names := make([]string, 0, len(allowedInternal))
	for k := range allowedInternal {
		names = append(names, k)
	}
	return names
}

// isBoundaryViolation reports whether a (possibly relative) import path
// refers to a NON-allowlisted internal/ package of THIS module. Relative
// same-module imports (e.g. "../internal/x" from pkg/node) are checked too;
// external modules that happen to contain "internal" are not.
func isBoundaryViolation(path string) bool {
	if allowedInternal[path] {
		return false
	}
	if strings.HasPrefix(path, modulePath+"/internal/") {
		return true
	}
	if strings.Contains(path, "..") {
		clean := strings.ReplaceAll(filepath.ToSlash(path), "\\", "/")
		if strings.Contains(clean, "internal/") {
			return true
		}
	}
	return false
}

// moduleRoot locates the repository root relative to this test file
// (internal/archtest/ → repo root is two levels up).
func moduleRoot(t *testing.T) string {
	t.Helper()
	here, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := filepath.Join(here, "..", "..")
	if st, err := os.Stat(filepath.Join(root, "go.mod")); err != nil || !st.Mode().IsRegular() {
		t.Fatalf("module root not found at %s (expected go.mod)", root)
	}
	return root
}
