// Package main derives, from the code, which database objects each Core
// role touches (role isolation design §3.2, TD-SEC-90 step S0).
//
// The roles are composed in one function, cmd/meshcore run(), whose top-level
// statements are gated by configuration sections (if processConfig.API !=
// nil, …). Each gate is mapped to the roles that load that section; every
// other top-level statement is shared by all roles. For each role, what its
// statements and the shared ones call, create (closures) or convert to
// interfaces (every method) are the roots of a rapid type analysis (RTA) of
// the whole program, together with the subcommands that open that role's
// database login. Every SQL text reachable from them is scanned for functions
// called and tables inserted, updated, deleted, locked or read.
//
// The analysis errs towards granting more:
//   - every method of a PostgreSQL adapter type a role allocates counts, not
//     only the methods RTA sees called;
//   - the logger's reflection makes every exported method of a value that
//     reaches it count;
//   - instructions without a position count for every role.
//
// It is checked for under-approximation by tests: every SQL function and
// written table named anywhere in Core is reached by a role or listed with a
// reason; SQL text that is assembled from fragments is listed and its parts
// are recognised. A grant missing from the result is a bug in this tool.
package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"slices"
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

const (
	commandPackage = "meshtransit.net/core/cmd/meshcore"
	composeFunc    = "run"
	sharedRegion   = "shared"
	adapterPrefix  = "meshtransit.net/core/internal/adapter/postgres"
)

// localGates maps local variables of run() that gate statements to roles:
// privateProfile is loaded only for api (config.loadPrivateLoginFile).
var localGates = map[string][]string{
	"privateProfile": {"api"},
}

// gateRoles maps each configuration section that gates a top-level statement
// of run() to the roles whose configuration loads it
// (internal/platform/config). A gate missing here, or a condition this tool
// cannot read exactly, fails the analysis, so a new gate is classified on
// purpose.
var gateRoles = map[string][]string{
	"API":                      {"api"},
	"FlowLogInternal":          {"api"},
	"Control":                  {"control"},
	"Identity":                 {"identity"},
	"RevisionWorker":           {"worker"},
	"PrivateEndpointWorker":    {"worker"},
	"DeviceAliasWorker":        {"worker"},
	"ContractExpiryWorker":     {"worker"},
	"NetworkSummaryWorker":     {"worker"},
	"NetworkDeletionWorker":    {"worker"},
	"SignedOutDeviceWorker":    {"worker"},
	"AccessLedgerWorker":       {"worker"},
	"KubernetesCAWorker":       {"worker"},
	"EnforcementLedgerWorker":  {"worker"},
	"AuthExpiry":               {"worker"},
	"PrivateLogin":             {sharedRegion},
	"BrowserRegistration":      {sharedRegion},
	"KubernetesAccessRequired": {sharedRegion},
	"Storage":                  {sharedRegion},
	"ProfileAddress":           {sharedRegion},
}

// subcommandRoots are functions of cmd/meshcore outside run() that open a
// serving role's login: meshcore kubernetes-ca uses the worker pool, meshcore
// config validate composes the api's private identity runtime.
var subcommandRoots = map[string][]string{
	"runKubernetesCA":   {"worker"},
	"runConfigValidate": {"api"},
}

// Roles are the roles reported; identity has its own database.
var Roles = []string{"api", "control", "worker"}

// Usage is what one role reaches. UPDATE and DELETE with a WHERE clause also
// need SELECT; a row lock (FOR UPDATE, FOR SHARE…) needs UPDATE.
type Usage struct {
	Functions []string `json:"functions"`
	Inserts   []string `json:"inserts"`
	Updates   []string `json:"updates"`
	Deletes   []string `json:"deletes"`
	Locks     []string `json:"locks"`
	Reads     []string `json:"reads"`
}

// Result is each role's usage, what all Core code (not tools) names, and the
// SQL fragments found, for the completeness checks.
type Result struct {
	Roles      map[string]Usage
	Everything Usage
	Fragments  []string
}

var (
	functionCall = regexp.MustCompile(`\b(mesh_ops|mesh_audit)\.([a-z_][a-z0-9_]*)\s*\(`)
	tableName    = `(mesh(?:_ops|_audit)?\.[a-z_][a-z0-9_]*)`
	tableInsert  = regexp.MustCompile(`(?i)\bINSERT\s+INTO\s+` + tableName + `\b`)
	tableUpdate  = regexp.MustCompile(`(?i)\bUPDATE\s+(?:ONLY\s+)?` + tableName + `\b`)
	tableDelete  = regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+(?:ONLY\s+)?` + tableName + `\b`)
	upsert       = regexp.MustCompile(`(?i)\bON\s+CONFLICT\b[^;]*\bDO\s+UPDATE\b`)
	tableRead    = regexp.MustCompile(`(?i)\b(?:FROM|JOIN)\s+(?:ONLY\s+)?` + tableName + `\b\s*([(]?)`)
	tableAlias   = regexp.MustCompile(`(?i)\b(?:FROM|JOIN|UPDATE)\s+(?:ONLY\s+)?` + tableName + `\s+(?:AS\s+)?([a-z_][a-z0-9_]*)`)
	rowLock      = regexp.MustCompile(`(?i)\bFOR\s+(?:UPDATE|NO\s+KEY\s+UPDATE|SHARE|KEY\s+SHARE)\b(?:\s+OF\s+([a-z_][a-z0-9_]*(?:\s*,\s*[a-z_][a-z0-9_]*)*))?`)
	// insertTarget is removed before looking for function calls: the column
	// list after INSERT INTO t is not a call.
	insertTarget = regexp.MustCompile(`(?i)\bINSERT\s+INTO\s+mesh(?:_ops|_audit)?\.[a-z_][a-z0-9_]*`)
	// fragment is SQL that names a schema but not the object: the name is
	// another constant, joined at run time or package initialisation.
	// A name cut short (mesh_ops.read_x_v + version) is a fragment too.
	fragment = regexp.MustCompile(`\bmesh(?:_ops|_audit)?\.(?:[^a-z_]|$|[a-z0-9_]*(?:_v|_)$)`)
	// versionedName is a bare function name constant (read_x_v2), the part
	// of a fragment: it counts as mesh_ops.<name>.
	versionedName = regexp.MustCompile(`^[a-z][a-z0-9_]*_v[0-9]+$`)
	sqlKeywords   = map[string]bool{"OF": true, "AS": true, "ON": true, "WHERE": true, "SET": true}
)

// Analyze loads the command from dir (the module root) for Linux and returns
// each role's usage. The dexbroker build needs a prepared Dex source tree and
// is not analysed: a test checks that no file behind that tag holds Core SQL.
func Analyze(dir string) (Result, error) {
	return analyzeBuild(dir, "")
}

func analyzeBuild(dir, tags string) (Result, error) {
	config := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes |
			packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
		Dir: dir,
		Env: append(slices.Clone(environ()), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0"),
	}
	if tags != "" {
		config.BuildFlags = []string{"-tags=" + tags}
	}
	loaded, err := packages.Load(config, commandPackage)
	if err != nil {
		return Result{}, fmt.Errorf("load %s: %w", commandPackage, err)
	}
	if packages.PrintErrors(loaded) > 0 || len(loaded) != 1 {
		return Result{}, errors.New("the command does not type-check")
	}
	program, ssaPackages := ssautil.AllPackages(loaded, ssa.InstantiateGenerics)
	program.Build()
	command := loaded[0]

	runDeclaration, spans, err := roleRegions(command)
	if err != nil {
		return Result{}, err
	}
	runFunction, err := functionNamed(program, command, runDeclaration.Name.Name)
	if err != nil {
		return Result{}, err
	}
	rootsByRegion := regionRoots(program, runFunction, spans)
	for name, roles := range subcommandRoots {
		root, err := functionNamed(program, command, name)
		if err != nil {
			return Result{}, err
		}
		for _, role := range roles {
			rootsByRegion[role] = append(rootsByRegion[role], root)
		}
	}
	// Package initialisers are not roots: they run no SQL, and their
	// compile-time interface assertions (var _ I = (*Store)(nil)) would make
	// every store a runtime type of every role. What they store into globals
	// (SQL in package-level structs, handler tables) is followed instead.
	globals := globalContentsOf(program, initialisers(ssaPackages))

	result := Result{Roles: map[string]Usage{}}
	for _, role := range Roles {
		roots := slices.Concat(rootsByRegion[sharedRegion], rootsByRegion[role])
		result.Roles[role] = scan(reach(program, roots, globals), globals, nil)
	}
	every := map[*ssa.Function]bool{}
	for function := range ssautil.AllFunctions(program) {
		if function.Pkg != nil && strings.HasPrefix(function.Pkg.Pkg.Path(), "meshtransit.net/core/") &&
			!strings.HasPrefix(function.Pkg.Pkg.Path(), "meshtransit.net/core/tools/") {
			every[function] = true
		}
	}
	fragments := map[string]bool{}
	result.Everything = scan(every, globals, fragments)
	result.Fragments = sorted(fragments)
	return result, nil
}

func functionNamed(program *ssa.Program, command *packages.Package, name string) (*ssa.Function, error) {
	object, ok := command.Types.Scope().Lookup(name).(*types.Func)
	if !ok {
		return nil, fmt.Errorf("%s.%s not found", commandPackage, name)
	}
	function := program.FuncValue(object)
	if function == nil {
		return nil, fmt.Errorf("%s.%s has no SSA function", commandPackage, name)
	}
	return function, nil
}

// span is one top-level statement of run() and the regions it belongs to.
type span struct {
	start, end token.Pos
	regions    []string
}

// roleRegions returns run() and, for each of its top-level statements, the
// regions (roles, or shared) it belongs to.
func roleRegions(command *packages.Package) (*ast.FuncDecl, []span, error) {
	var run *ast.FuncDecl
	for _, file := range command.Syntax {
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Recv == nil &&
				function.Name.Name == composeFunc {
				run = function
			}
		}
	}
	if run == nil {
		return nil, nil, fmt.Errorf("%s.%s not found", commandPackage, composeFunc)
	}
	var spans []span
	for _, statement := range run.Body.List {
		region := []string{sharedRegion}
		if gated, ok := statement.(*ast.IfStmt); ok {
			roles, err := conditionRoles(gated.Cond)
			if err != nil {
				return nil, nil, fmt.Errorf("run() at %s: %w", command.Fset.Position(gated.Pos()), err)
			}
			if roles != nil {
				if gated.Else != nil || gated.Init != nil {
					return nil, nil, fmt.Errorf("run() at %s: a gated statement has an else branch or an init "+
						"statement, which runs in every role", command.Fset.Position(gated.Pos()))
				}
				region = roles
			}
		}
		spans = append(spans, span{start: statement.Pos(), end: statement.End(), regions: region})
	}
	return run, spans, nil
}

// conditionRoles reads an if condition: nil when it does not gate by role;
// the roles of one gate (processConfig.X != nil, processConfig.X != "", a
// bare processConfig.X, or a gating local != nil); the intersection for
// gate && gate. Anything else naming processConfig is an error.
func conditionRoles(condition ast.Expr) ([]string, error) {
	if binary, ok := condition.(*ast.BinaryExpr); ok && binary.Op == token.LAND {
		left, err := conditionRoles(binary.X)
		if err != nil {
			return nil, err
		}
		right, err := conditionRoles(binary.Y)
		if err != nil {
			return nil, err
		}
		return intersect(left, right), nil
	}
	if gate, ok := singleGate(condition); ok {
		return gate, nil
	}
	mentions := false
	ast.Inspect(condition, func(node ast.Node) bool {
		if identifier, ok := node.(*ast.Ident); ok && (identifier.Name == "processConfig" ||
			localGates[identifier.Name] != nil) {
			mentions = true
		}
		return !mentions
	})
	if mentions {
		return nil, errors.New("a condition on processConfig or a gating local is not a plain gate")
	}
	return nil, nil
}

// singleGate reads one gate.
func singleGate(condition ast.Expr) ([]string, bool) {
	field := func(expression ast.Expr) (string, bool) {
		selector, ok := expression.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		base, ok := selector.X.(*ast.Ident)
		return selector.Sel.Name, ok && base.Name == "processConfig"
	}
	if name, ok := field(condition); ok {
		roles, known := gateRoles[name]
		return roles, known
	}
	binary, ok := condition.(*ast.BinaryExpr)
	if !ok || binary.Op != token.NEQ {
		return nil, false
	}
	empty := false
	switch value := binary.Y.(type) {
	case *ast.Ident:
		empty = value.Name == "nil"
	case *ast.BasicLit:
		empty = value.Kind == token.STRING && value.Value == `""`
	}
	if !empty {
		return nil, false
	}
	if name, ok := field(binary.X); ok {
		roles, known := gateRoles[name]
		return roles, known
	}
	if local, ok := binary.X.(*ast.Ident); ok {
		roles, known := localGates[local.Name]
		return roles, known
	}
	return nil, false
}

// intersect combines two gates: shared (or no gate) leaves the other. Gates
// with no role in common give nil, so the statement counts as shared, which
// only grants more.
func intersect(left, right []string) []string {
	switch {
	case left == nil || slices.Equal(left, []string{sharedRegion}):
		return right
	case right == nil || slices.Equal(right, []string{sharedRegion}):
		return left
	}
	var both []string
	for _, role := range left {
		if slices.Contains(right, role) {
			both = append(both, role)
		}
	}
	return both
}

// regionRoots assigns every instruction of run() to the region of its
// statement and returns per region: functions called, functions and closures
// created, and every method of a concrete type converted to an interface.
func regionRoots(program *ssa.Program, run *ssa.Function, spans []span) map[string][]*ssa.Function {
	roots := map[string][]*ssa.Function{}
	regionsAt := func(position token.Pos) []string {
		for _, candidate := range spans {
			if position >= candidate.start && position < candidate.end {
				return candidate.regions
			}
		}
		return []string{sharedRegion}
	}
	for _, block := range run.Blocks {
		for _, instruction := range block.Instrs {
			position := instruction.Pos()
			if value, ok := instruction.(ssa.Value); ok && position == token.NoPos {
				position = value.Pos()
			}
			for _, region := range regionsAt(position) {
				roots[region] = append(roots[region], instructionRoots(program, instruction)...)
			}
		}
	}
	return roots
}

// instructionRoots are the functions one instruction makes callable.
func instructionRoots(program *ssa.Program, instruction ssa.Instruction) []*ssa.Function {
	var roots []*ssa.Function
	if call, ok := instruction.(ssa.CallInstruction); ok {
		if callee := call.Common().StaticCallee(); callee != nil {
			roots = append(roots, callee)
		}
	}
	switch value := instruction.(type) {
	case *ssa.MakeClosure:
		if function, ok := value.Fn.(*ssa.Function); ok {
			roots = append(roots, function)
		}
	case *ssa.MakeInterface:
		roots = append(roots, methodsOf(program, value.X.Type())...)
	}
	for _, operand := range instruction.Operands(nil) {
		if operand != nil && *operand != nil {
			if function, ok := (*operand).(*ssa.Function); ok {
				roots = append(roots, function)
			}
		}
	}
	return roots
}

func methodsOf(program *ssa.Program, typ types.Type) []*ssa.Function {
	var methods []*ssa.Function
	set := program.MethodSets.MethodSet(typ)
	for index := range set.Len() {
		if method := program.MethodValue(set.At(index)); method != nil {
			methods = append(methods, method)
		}
	}
	return methods
}

// reach runs RTA from roots to a fixpoint that adds, as roots, (a) the
// functions and methods package initialisers stored into globals reachable
// code reads, and (b) every method of a PostgreSQL adapter type reachable
// code allocates, so a store built for a role counts whole.
func reach(program *ssa.Program, roots []*ssa.Function, globals globalContents) map[*ssa.Function]bool {
	known := map[*ssa.Function]bool{}
	for _, root := range roots {
		known[root] = true
	}
	for {
		result := rta.Analyze(roots, false)
		added := false
		add := func(function *ssa.Function) {
			if function != nil && !known[function] {
				known[function] = true
				roots = append(roots, function)
				added = true
			}
		}
		for function := range result.Reachable {
			for _, block := range function.Blocks {
				for _, instruction := range block.Instrs {
					if allocation, ok := instruction.(*ssa.Alloc); ok && adapterType(allocation.Type()) {
						for _, method := range methodsOf(program, allocation.Type()) {
							add(method)
						}
					}
					for _, operand := range instruction.Operands(nil) {
						if operand == nil || *operand == nil {
							continue
						}
						if global, ok := (*operand).(*ssa.Global); ok {
							for _, stored := range globals.functions[global] {
								add(stored)
							}
						}
					}
				}
			}
		}
		if !added {
			reachable := make(map[*ssa.Function]bool, len(result.Reachable))
			for function := range result.Reachable {
				reachable[function] = true
			}
			return reachable
		}
	}
}

// adapterType reports a pointer to a named type of the PostgreSQL adapter.
func adapterType(typ types.Type) bool {
	pointer, ok := typ.(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := pointer.Elem().(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	return strings.HasPrefix(named.Obj().Pkg().Path(), adapterPrefix)
}

// initialisers returns every package initialiser.
func initialisers(ssaPackages []*ssa.Package) []*ssa.Function {
	var roots []*ssa.Function
	for _, ssaPackage := range ssaPackages {
		if ssaPackage != nil {
			if init := ssaPackage.Func("init"); init != nil {
				roots = append(roots, init)
			}
		}
	}
	return roots
}

// globalContents records what package initialisers store into globals.
type globalContents struct {
	strings   map[*ssa.Global][]string
	functions map[*ssa.Global][]*ssa.Function
}

// globalContentsOf returns, for each global, the string constants and the
// functions (and methods of values converted to interfaces) that package
// initialisers store into it, its fields, elements or map entries. A value
// computed by a call contributes every constant the callee and its callees
// use (SQL assembled by a helper).
func globalContentsOf(program *ssa.Program, initialisers []*ssa.Function) globalContents {
	result := globalContents{strings: map[*ssa.Global][]string{}, functions: map[*ssa.Global][]*ssa.Function{}}
	locals := map[ssa.Value][]string{}
	localFunctions := map[ssa.Value][]*ssa.Function{}
	functionsOf := func(value ssa.Value) []*ssa.Function {
		switch value := value.(type) {
		case *ssa.Function:
			return []*ssa.Function{value}
		case *ssa.MakeClosure:
			if function, ok := value.Fn.(*ssa.Function); ok {
				return []*ssa.Function{function}
			}
		case *ssa.MakeInterface:
			if function, ok := value.X.(*ssa.Function); ok {
				return []*ssa.Function{function}
			}
			return methodsOf(program, value.X.Type())
		}
		return nil
	}
	stringsOf := func(value ssa.Value) []string {
		switch value := value.(type) {
		case *ssa.Const:
			if value.Value != nil && value.Value.Kind() == constant.String {
				return []string{constant.StringVal(value.Value)}
			}
		case *ssa.Call:
			texts := calleeStrings(value.Call.StaticCallee(), map[*ssa.Function]bool{})
			for _, argument := range value.Call.Args {
				if argumentConst, ok := argument.(*ssa.Const); ok && argumentConst.Value != nil &&
					argumentConst.Value.Kind() == constant.String {
					texts = append(texts, constant.StringVal(argumentConst.Value))
				}
			}
			return texts
		}
		return nil
	}
	containerOf := func(value ssa.Value) ssa.Value {
		switch value := value.(type) {
		case *ssa.Slice:
			return rootAddress(value.X)
		case *ssa.MakeMap, *ssa.Alloc:
			return value
		case *ssa.UnOp:
			if value.Op == token.MUL {
				return rootAddress(value.X)
			}
		}
		return nil
	}
	seen := map[*ssa.Function]bool{}
	var visit func(function *ssa.Function)
	visit = func(function *ssa.Function) {
		if function == nil || seen[function] {
			return
		}
		seen[function] = true
		for _, block := range function.Blocks {
			for _, instruction := range block.Instrs {
				switch instruction := instruction.(type) {
				case *ssa.MapUpdate:
					localFunctions[instruction.Map] = append(localFunctions[instruction.Map],
						functionsOf(instruction.Value)...)
					locals[instruction.Map] = append(locals[instruction.Map], stringsOf(instruction.Value)...)
				case *ssa.Call:
					// Initialisers call the next package's init and their own
					// helpers; both may store into globals.
					if callee := instruction.Call.StaticCallee(); callee != nil &&
						strings.HasPrefix(callee.Name(), "init") {
						visit(callee)
					}
				case *ssa.Store:
					root := rootAddress(instruction.Addr)
					if root == nil {
						continue
					}
					texts := stringsOf(instruction.Val)
					functions := functionsOf(instruction.Val)
					if source := containerOf(instruction.Val); source != nil {
						texts = append(texts, locals[source]...)
						functions = append(functions, localFunctions[source]...)
					}
					if global, ok := root.(*ssa.Global); ok {
						result.strings[global] = append(result.strings[global], texts...)
						result.functions[global] = append(result.functions[global], functions...)
					} else {
						locals[root] = append(locals[root], texts...)
						localFunctions[root] = append(localFunctions[root], functions...)
					}
				}
			}
		}
	}
	for _, function := range initialisers {
		visit(function)
	}
	return result
}

// calleeStrings returns every string constant a function and its static
// callees use.
func calleeStrings(function *ssa.Function, seen map[*ssa.Function]bool) []string {
	if function == nil || seen[function] {
		return nil
	}
	seen[function] = true
	var texts []string
	for _, block := range function.Blocks {
		for _, instruction := range block.Instrs {
			for _, operand := range instruction.Operands(nil) {
				if operand == nil || *operand == nil {
					continue
				}
				if value, ok := (*operand).(*ssa.Const); ok && value.Value != nil &&
					value.Value.Kind() == constant.String {
					texts = append(texts, constant.StringVal(value.Value))
				}
			}
			if call, ok := instruction.(ssa.CallInstruction); ok {
				texts = append(texts, calleeStrings(call.Common().StaticCallee(), seen)...)
			}
		}
	}
	return texts
}

// rootAddress follows field and element addresses back to a global or a
// local allocation.
func rootAddress(address ssa.Value) ssa.Value {
	for {
		switch value := address.(type) {
		case *ssa.Global, *ssa.Alloc:
			return value
		case *ssa.FieldAddr:
			address = value.X
		case *ssa.IndexAddr:
			address = value.X
		default:
			return nil
		}
	}
}

// scan collects the database objects named by every string constant used in
// the functions, and by the constants package initialisers store into
// globals they read. Fragments, when not nil, receives SQL texts that name a
// schema without the object.
func scan(functions map[*ssa.Function]bool, globals globalContents, fragments map[string]bool) Usage {
	names := map[string]map[string]bool{
		"functions": {}, "inserts": {}, "updates": {}, "deletes": {}, "locks": {}, "reads": {},
	}
	// record scans one group of texts that are joined together (one
	// function's constants, or what initialisers stored into one global): a
	// bare versioned name counts as a mesh_ops function only next to a
	// schema fragment it completes.
	record := func(texts []string) {
		completes := slices.ContainsFunc(texts, fragment.MatchString)
		for _, text := range texts {
			if completes && versionedName.MatchString(text) {
				names["functions"]["mesh_ops."+text] = true
				continue
			}
			if !strings.Contains(text, "mesh") {
				continue
			}
			if fragments != nil && fragment.MatchString(text) {
				fragments[text] = true
			}
			recordSQL(text, names)
		}
	}
	for function := range functions {
		var texts []string
		for _, block := range function.Blocks {
			for _, instruction := range block.Instrs {
				for _, operand := range instruction.Operands(nil) {
					if operand == nil || *operand == nil {
						continue
					}
					switch value := (*operand).(type) {
					case *ssa.Const:
						if value.Value != nil && value.Value.Kind() == constant.String {
							texts = append(texts, constant.StringVal(value.Value))
						}
					case *ssa.Global:
						record(globals.strings[value])
					}
				}
			}
		}
		record(texts)
	}
	return Usage{
		Functions: sorted(names["functions"]), Inserts: sorted(names["inserts"]),
		Updates: sorted(names["updates"]), Deletes: sorted(names["deletes"]),
		Locks: sorted(names["locks"]), Reads: sorted(names["reads"]),
	}
}

// recordSQL adds the objects one SQL text names.
func recordSQL(text string, names map[string]map[string]bool) {
	for _, match := range functionCall.FindAllStringSubmatch(insertTarget.ReplaceAllString(text, "INSERT"), -1) {
		names["functions"][match[1]+"."+match[2]] = true
	}
	inserted := tableInsert.FindAllStringSubmatch(text, -1)
	for _, match := range inserted {
		names["inserts"][strings.ToLower(match[1])] = true
	}
	if upsert.MatchString(text) {
		for _, match := range inserted {
			names["updates"][strings.ToLower(match[1])] = true
		}
	}
	for _, match := range tableUpdate.FindAllStringSubmatch(text, -1) {
		names["updates"][strings.ToLower(match[1])] = true
	}
	for _, match := range tableDelete.FindAllStringSubmatch(text, -1) {
		names["deletes"][strings.ToLower(match[1])] = true
	}
	read := []string{}
	for _, match := range tableRead.FindAllStringSubmatch(text, -1) {
		if match[2] == "" {
			table := strings.ToLower(match[1])
			names["reads"][table] = true
			read = append(read, table)
		}
	}
	for _, lock := range rowLock.FindAllStringSubmatch(text, -1) {
		if lock[1] == "" {
			// FOR UPDATE without OF locks every table read.
			for _, table := range read {
				names["locks"][table] = true
			}
			continue
		}
		aliases := map[string]string{}
		ambiguous := map[string]bool{}
		for _, match := range tableAlias.FindAllStringSubmatch(text, -1) {
			if sqlKeywords[strings.ToUpper(match[2])] {
				continue
			}
			alias, table := strings.ToLower(match[2]), strings.ToLower(match[1])
			if known, ok := aliases[alias]; ok && known != table {
				ambiguous[alias] = true
			}
			aliases[alias] = table
		}
		for _, alias := range strings.Split(lock[1], ",") {
			alias = strings.ToLower(strings.TrimSpace(alias))
			if table, ok := aliases[alias]; ok && !ambiguous[alias] {
				names["locks"][table] = true
			} else {
				// An alias this scan cannot resolve, or one naming two
				// tables, locks every table read.
				for _, table := range read {
					names["locks"][table] = true
				}
			}
		}
	}
}

func sorted(set map[string]bool) []string {
	list := make([]string, 0, len(set))
	for item := range set {
		list = append(list, item)
	}
	sort.Strings(list)
	return list
}
