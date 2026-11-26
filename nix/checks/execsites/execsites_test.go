// Package execsites checks S12 (models/README.md) over the Go sources: no host-side process execs with capabilities
// in a sandbox namespace on a mount tree the sandbox can swap a directory in. Today that holds because every such exec
// goes through nsenter without the mount namespace, on the host's mounts, and the one helper that joins M1 does so
// itself, after its exec, and execs nothing after. Nothing in the kernel or the build keeps the next helper to that,
// so these tests do: a function that names nsenter, joins a namespace or reaches an exec after joining M1 fails them
// until it is listed here with what it may do.
//
// The checks read syntax, not types: they follow calls within a package by name, so an exec behind an interface, a
// function value or another package's function isn't seen. TestRulesCatch runs them on sources that break each rule.
package execsites

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// What a function that names nsenter does with it
type class int

const (
	// Execs nsenter with the capabilities kept (--keep-caps, or uid 0 without --preserve-credentials), so on the
	// host's mounts: the user, net and uts namespaces only, each by a file descriptor the caller pinned
	hostMounts class = iota
	// The re-entry: joins the app's mount namespace and execs a path there, so without capabilities, under
	// no_new_privs set on the host
	reentry
	// Hands nsenter's path to another listed function
	passes
)

type site struct {
	class class
	extra []string // Options of the tool nsenter runs, beside nsenter's own
}

// Every function outside the tests that names nsenter, as <file>:<function>
var sites = map[string]site{
	"cmd/launcher/enter.go:enter":                            {class: reentry},
	"cmd/launcher/helper.go:ipIn":                            {class: hostMounts, extra: []string{"-batch", "-"}},
	"cmd/launcher/helper.go:runIn":                           {class: hostMounts},
	"cmd/launcher/helper.go:netSetup.run":                    {class: passes},
	"cmd/launcher/helper.go:netSetup.hooks":                  {class: passes},
	"cmd/launcher/helper.go:sandboxRoutes":                   {class: passes},
	"cmd/launcher/dns.go:dns.syncRoutes":                     {class: passes},
	"cmd/permissions-broker/internal/mounts/helpers.go:inM1": {class: hostMounts},
	"cmd/permissions-broker/internal/mounts/tree.go:Attach":  {class: hostMounts},
	"cmd/subid-broker/main.go:handle":                        {class: hostMounts},
}

// The functions that join a namespace themselves (setns), and those that call them: each joins M1 after its exec on
// the host's mounts and must reach no exec after
var joins = map[string][]string{
	"cmd/permissions-broker/internal/mounts/helpers.go:enterM1": {"MakeShared", "MoveTree", "DetachHelper"},
}

var (
	nsFlag = regexp.MustCompile(`^--(user|net|uts)=/proc/self/fd/[0-9]+$`)
	// nsenter's options that keep or give capabilities through its exec, or take what the sandbox chose
	keepsCaps = []string{"--keep-caps", "-S", "--setuid", "-G", "--setgid", "-e", "--env"}
	execCalls = []string{"Command", "CommandContext", "Exec", "ForkExec", "StartProcess"}
)

type fn struct {
	key, dir, name string
	decl           *ast.FuncDecl
}

// parse reads the non-test Go sources, by path relative to the module's root
func parse(sources map[string]string) ([]fn, error) {
	var fns []fn
	fset := token.NewFileSet()
	for path, src := range sources {
		f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			name := fd.Name.Name
			if fd.Recv != nil && len(fd.Recv.List) == 1 {
				t := fd.Recv.List[0].Type
				if star, ok := t.(*ast.StarExpr); ok {
					t = star.X
				}
				if id, ok := t.(*ast.Ident); ok {
					name = id.Name + "." + name
				}
			}
			fns = append(fns, fn{key: path + ":" + name, dir: filepath.Dir(path), name: name, decl: fd})
		}
	}
	sort.Slice(fns, func(i, j int) bool { return fns[i].key < fns[j].key })
	return fns, nil
}

func isNsenter(n ast.Node) bool {
	switch n := n.(type) {
	case *ast.Ident:
		return strings.EqualFold(n.Name, "nsenter")
	case *ast.BasicLit:
		s, err := strconv.Unquote(n.Value)
		return err == nil && filepath.Base(s) == "nsenter"
	}
	return false
}

func names(root ast.Node, pred func(ast.Node) bool) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if n != nil && pred(n) {
			found = true
		}
		return !found
	})
	return found
}

// options are the string literals of root that start with a dash
func options(root ast.Node) []string {
	var opts []string
	ast.Inspect(root, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil && strings.HasPrefix(s, "-") {
				opts = append(opts, s)
			}
		}
		return true
	})
	return opts
}

// selCalls are root's calls of the form x.Name(...), as "x.Name"
func selCalls(root ast.Node) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(root, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if _, ok := c.Fun.(*ast.SelectorExpr); ok {
				calls = append(calls, c)
			}
		}
		return true
	})
	return calls
}

func selName(c *ast.CallExpr) string { return c.Fun.(*ast.SelectorExpr).Sel.Name }

// execs reports whether root starts a process: os/exec, syscall's or unix's exec, os.StartProcess
func execs(root ast.Node) bool {
	for _, c := range selCalls(root) {
		if slices.Contains(execCalls, selName(c)) {
			return true
		}
	}
	return false
}

// checkSites checks every function that names nsenter against its entry of sites
func checkSites(fns []fn, sites map[string]site) []string {
	var bad []string
	seen := map[string]bool{}
	for _, f := range fns {
		if !names(f.decl.Body, isNsenter) {
			continue
		}
		seen[f.key] = true
		s, ok := sites[f.key]
		if !ok {
			bad = append(bad, f.key+" names nsenter and isn't listed: say what it may do with it")
			continue
		}
		opts := options(f.decl.Body)
		switch s.class {
		case passes:
			// Its calls with nsenter among the arguments go to listed functions of its package, none starts a process
			for _, c := range selCalls(f.decl.Body) {
				if slices.Contains(execCalls, selName(c)) && slices.ContainsFunc(c.Args, func(a ast.Expr) bool { return names(a, isNsenter) }) {
					bad = append(bad, f.key+" runs nsenter itself, and is listed as passing it on")
				}
			}
			ast.Inspect(f.decl.Body, func(n ast.Node) bool {
				if lit, ok := n.(*ast.CompositeLit); ok && slices.ContainsFunc(lit.Elts, isExprNsenter) {
					bad = append(bad, f.key+" builds nsenter's arguments itself, and is listed as passing it on")
				}
				return true
			})
		case hostMounts:
			for _, o := range opts {
				if !nsFlag.MatchString(o) && !slices.Contains([]string{"--preserve-credentials", "--keep-caps", "--"}, o) &&
					!slices.Contains(s.extra, o) {
					bad = append(bad, fmt.Sprintf("%s runs nsenter with capabilities and %s: only the user, net and uts "+
						"namespaces by a pinned fd, so its exec resolves on the host's mounts", f.key, o))
				}
			}
			if !slices.ContainsFunc(opts, func(o string) bool { return strings.HasPrefix(o, "--user=") }) {
				bad = append(bad, f.key+" is listed as running nsenter with capabilities, and joins no user namespace")
			}
		case reentry:
			for _, want := range []string{"--no-new-privs", "--preserve-credentials", "-m"} {
				if !slices.Contains(opts, want) {
					bad = append(bad, fmt.Sprintf("%s joins the app's mount namespace without %s", f.key, want))
				}
			}
			for _, o := range opts {
				if slices.Contains(keepsCaps, o) {
					bad = append(bad, fmt.Sprintf("%s execs a path of the sandbox's with %s", f.key, o))
				}
			}
		}
	}
	for key := range sites {
		if !seen[key] {
			bad = append(bad, key+" is listed and doesn't name nsenter: remove it")
		}
	}
	sort.Strings(bad)
	return bad
}

func isExprNsenter(e ast.Expr) bool { return names(e, isNsenter) }

// checkJoins checks that only the listed functions call setns, that only the listed ones call those, and that none of
// them reaches an exec through its package's functions
func checkJoins(fns []fn, joins map[string][]string) []string {
	var bad []string
	byName := map[string]map[string]fn{}
	for _, f := range fns {
		if byName[f.dir] == nil {
			byName[f.dir] = map[string]fn{}
		}
		byName[f.dir][f.name] = f
	}
	callees := func(f fn) []fn {
		var out []fn
		ast.Inspect(f.decl.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok {
					if g, ok := byName[f.dir][id.Name]; ok {
						out = append(out, g)
					}
				}
			}
			return true
		})
		return out
	}
	seen := map[string]bool{}
	for _, f := range fns {
		setns := slices.ContainsFunc(selCalls(f.decl.Body), func(c *ast.CallExpr) bool { return selName(c) == "Setns" })
		callers, listed := joins[f.key]
		if setns && !listed {
			bad = append(bad, f.key+" joins a namespace (setns) and isn't listed: say who may call it")
		}
		if !setns || !listed {
			continue
		}
		seen[f.key] = true
		var got []string
		for _, g := range fns {
			if g.dir != f.dir || g.key == f.key {
				continue
			}
			if slices.ContainsFunc(callees(g), func(c fn) bool { return c.key == f.key }) {
				got = append(got, g.name)
				// What g reaches, itself included
				reach, queue := map[string]bool{g.key: true}, []fn{g}
				for len(queue) > 0 {
					h := queue[0]
					queue = queue[1:]
					if execs(h.decl.Body) {
						bad = append(bad, fmt.Sprintf("%s joins the sandbox's mount namespace through %s and reaches an "+
							"exec in %s: its path would resolve where the sandbox swaps directories", g.key, f.name, h.key))
					}
					for _, c := range callees(h) {
						if !reach[c.key] {
							reach[c.key] = true
							queue = append(queue, c)
						}
					}
				}
			}
		}
		sort.Strings(got)
		want := slices.Clone(callers)
		sort.Strings(want)
		if !slices.Equal(got, want) {
			bad = append(bad, fmt.Sprintf("%s is called by %v, listed %v", f.key, got, want))
		}
	}
	for key := range joins {
		if !seen[key] {
			bad = append(bad, key+" is listed and doesn't call setns: remove it")
		}
	}
	sort.Strings(bad)
	return bad
}

// The module's non-test Go sources in cmd/ and internal/
func moduleSources(t *testing.T) map[string]string {
	root := "../../.."
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("Not at nix/checks/execsites of the module: %v", err)
	}
	sources := map[string]string{}
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			data, err := os.ReadFile(path)
			rel, _ := filepath.Rel(root, path)
			sources[rel] = string(data)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// Each binary's package builds from a source of its own: this check wants them all
	for _, want := range []string{"cmd/launcher/enter.go", "cmd/permissions-broker/main.go", "cmd/subid-broker/main.go"} {
		if _, ok := sources[want]; !ok {
			t.Fatalf("%s is missing from the sources", want)
		}
	}
	return sources
}

// S12: the module's own sources
func TestHostExecs(t *testing.T) {
	fns, err := parse(moduleSources(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range append(checkSites(fns, sites), checkJoins(fns, joins)...) {
		t.Error(b)
	}
}
