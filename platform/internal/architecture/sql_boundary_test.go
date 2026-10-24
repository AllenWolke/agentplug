package architecture_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// Dynamic queries require reviewed, source-bound registrations. Never infer
// approval from the current implementation. / 动态 SQL 必须显式审阅并绑定源码摘要。
type dynamicSQLRegistration struct {
	SourceSHA256 string   `json:"source_sha256"`
	Forwarding   bool     `json:"forwarding,omitempty"`
	Tables       []string `json:"tables"`
	Reason       string   `json:"reason"`
}

type sqlSite struct {
	Function   string
	Expression string
	Text       string
	Complete   bool
	Line       int
}

func renderSQL(expr ast.Expr, constants map[string]ast.Expr, visited map[string]bool) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			value, err := strconv.Unquote(e.Value)
			return value, err == nil
		}
	case *ast.ParenExpr:
		return renderSQL(e.X, constants, visited)
	case *ast.CallExpr:
		if selector, ok := e.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Bind" && len(e.Args) == 1 {
			if receiver, ok := selector.X.(*ast.Ident); ok && receiver.Name == "sqlutil" {
				return renderSQL(e.Args[0], constants, visited)
			}
		}
	case *ast.CompositeLit:
		var parts []string
		complete := true
		for _, element := range e.Elts {
			text, known := renderSQL(element, constants, visited)
			parts = append(parts, text)
			complete = complete && known
		}
		return strings.Join(parts, "; "), complete
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			a, ac := renderSQL(e.X, constants, visited)
			b, bc := renderSQL(e.Y, constants, visited)
			return a + b, ac && bc
		}
	case *ast.Ident:
		if value, ok := constants[e.Name]; ok && !visited[e.Name] {
			visited[e.Name] = true
			text, complete := renderSQL(value, constants, visited)
			delete(visited, e.Name)
			return text, complete
		}
	}
	return "{{dynamic}}", false
}

func sqlSites(source []byte, inherited map[string]ast.Expr) ([]sqlSite, error) {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "source.go", source, 0)
	if err != nil {
		return nil, err
	}
	constants := map[string]ast.Expr{}
	for key, value := range inherited {
		constants[key] = value
	}
	for _, decl := range file.Decls {
		general, ok := decl.(*ast.GenDecl)
		if !ok || general.Tok != token.CONST {
			continue
		}
		for _, specification := range general.Specs {
			value := specification.(*ast.ValueSpec)
			for i, name := range value.Names {
				if i < len(value.Values) {
					constants[name.Name] = value.Values[i]
				}
			}
		}
	}
	var sites []sqlSite
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		name := function.Name.Name
		if function.Recv != nil {
			var receiver bytes.Buffer
			_ = printer.Fprint(&receiver, set, function.Recv.List[0].Type)
			name = receiver.String() + "." + name
		}
		local := map[string]ast.Expr{}
		for key, value := range constants {
			local[key] = value
		}
		// Consider every local assignment, not just the final branch. Unknown
		// values remain dynamic; finite literal branches are all checked.
		// 检查所有分支赋值；未知值保持动态，有限字面量分支逐一检查。
		bind := func(name string, value ast.Expr, appendValue bool) {
			if old, exists := local[name]; exists {
				if appendValue {
					local[name] = &ast.BinaryExpr{X: old, Op: token.ADD, Y: value}
				} else {
					local[name] = &ast.CompositeLit{Elts: []ast.Expr{old, value}}
				}
			} else {
				local[name] = value
			}
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch item := node.(type) {
			case *ast.AssignStmt:
				for i, left := range item.Lhs {
					id, ok := left.(*ast.Ident)
					if ok && i < len(item.Rhs) {
						bind(id.Name, item.Rhs[i], item.Tok == token.ADD_ASSIGN)
					}
				}
			case *ast.ValueSpec:
				for i, id := range item.Names {
					if i < len(item.Values) {
						bind(id.Name, item.Values[i], false)
					}
				}
			case *ast.RangeStmt:
				if id, ok := item.Value.(*ast.Ident); ok {
					bind(id.Name, item.X, false)
				}
			}
			return true
		})
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			method, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			index := -1
			switch method.Sel.Name {
			case "Exec", "Query", "QueryRow", "Prepare":
				index = 0
			case "ExecContext", "QueryContext", "QueryRowContext", "PrepareContext":
				index = 1
			}
			if index < 0 || index >= len(call.Args) {
				return true
			}
			// database/sql Prepare has exactly one argument, PrepareContext
			// exactly two. Domain planning methods with other signatures are
			// not SQL sites. Exec/Query retain their variadic argument checks.
			if (method.Sel.Name == "Prepare" && len(call.Args) != 1) ||
				(method.Sel.Name == "PrepareContext" && len(call.Args) != 2) {
				return true
			}
			expr := call.Args[index]
			text, complete := renderSQL(expr, local, map[string]bool{})
			var expression bytes.Buffer
			if err := printer.Fprint(&expression, set, expr); err != nil {
				text, complete = "{{print-error}}", false
			}
			sites = append(sites, sqlSite{name, expression.String(), text, complete, set.Position(call.Pos()).Line})
			return true
		})
	}
	return sites, nil
}

var tableReference = regexp.MustCompile("(?i)\\b(?:INSERT\\s+(?:IGNORE\\s+)?INTO|UPDATE|DELETE\\s+FROM|REPLACE\\s+INTO|FROM|JOIN|CREATE\\s+TABLE\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?|ALTER\\s+TABLE|DROP\\s+TABLE\\s+(?:IF\\s+EXISTS\\s+)?)\\s+(?:LATERAL\\s+)?[`\"]?([a-z_][a-z0-9_]*(?:\\.[a-z_][a-z0-9_]*)?)[`\"]?")

var cteDeclaration = regexp.MustCompile(`(?i)(?:\bWITH|,)\s+([a-z_][a-z0-9_]*)\s+AS\s+(?:MATERIALIZED\s+)?\(`)

// Preserve offsets while hiding text that cannot declare a CTE. Quoted
// identifiers remain subject to table ownership checks in the original SQL.
func sqlScopeCode(query string) string {
	code := []byte(query)
	dollar := regexp.MustCompile(`^\$(?:[a-zA-Z_][a-zA-Z0-9_]*)?\$`)
	for i := 0; i < len(query); {
		start := i
		switch {
		case strings.HasPrefix(query[i:], "--"):
			for i < len(query) && query[i] != '\n' {
				i++
			}
		case strings.HasPrefix(query[i:], "/*"):
			i += 2
			for depth := 1; i < len(query) && depth > 0; {
				if strings.HasPrefix(query[i:], "/*") {
					depth++
					i += 2
				} else if strings.HasPrefix(query[i:], "*/") {
					depth--
					i += 2
				} else {
					i++
				}
			}
		case query[i] == '\'' || query[i] == '"' || query[i] == '`':
			quote := query[i]
			i++
			for i < len(query) {
				if query[i] == '\\' && quote == '\'' && i+1 < len(query) {
					i += 2
				} else if query[i] == quote {
					i++
					if i < len(query) && query[i] == quote {
						i++
					} else {
						break
					}
				} else {
					i++
				}
			}
		case query[i] == '$' && dollar.FindString(query[i:]) != "":
			tag := dollar.FindString(query[i:])
			i += len(tag)
			if end := strings.Index(query[i:], tag); end >= 0 {
				i += end + len(tag)
			} else {
				i = len(query)
			}
		default:
			i++
			continue
		}
		for j := start; j < i; j++ {
			code[j] = ' '
		}
	}
	return string(code)
}

type cteScope struct{ start, end int }

// A CTE is a read alias only after its body and within its enclosing query.
// A same-named DML target is always a physical table.
func completedCTEs(query string) map[string][]cteScope {
	code := sqlScopeCode(query)
	result := map[string][]cteScope{}
	parents := make([]int, len(code))
	closes := map[int]int{}
	var stack []int
	for i := range code {
		parents[i] = -1
		if len(stack) > 0 {
			parents[i] = stack[len(stack)-1]
		}
		if code[i] == '(' {
			stack = append(stack, i)
		} else if code[i] == ')' && len(stack) > 0 {
			closes[stack[len(stack)-1]] = i
			stack = stack[:len(stack)-1]
		}
	}
	for _, match := range cteDeclaration.FindAllStringSubmatchIndex(code, -1) {
		bodyEnd, ok := closes[match[1]-1]
		if !ok {
			continue
		}
		end := len(code)
		if parent := parents[match[0]]; parent >= 0 {
			if end, ok = closes[parent]; !ok {
				continue
			}
		}
		if separator := strings.IndexByte(code[bodyEnd+1:end], ';'); separator >= 0 {
			end = bodyEnd + 1 + separator
		}
		name := strings.ToLower(code[match[2]:match[3]])
		result[name] = append(result[name], cteScope{bodyEnd + 1, end})
	}
	return result
}

func cteReadAt(scopes []cteScope, position int) bool {
	for _, scope := range scopes {
		if position >= scope.start && position < scope.end {
			return true
		}
	}
	return false
}

func nonTableUpdate(query string, position int, table string) bool {
	prefix := query[:position]
	return regexp.MustCompile(`(?i)\bFOR(?:\s+NO\s+KEY)?\s*$`).MatchString(prefix) ||
		(table == "set" && regexp.MustCompile(`(?i)\bDO\s*$`).MatchString(prefix)) ||
		((table == "or" || table == "of" || table == "on") && regexp.MustCompile(`(?i)\b(?:BEFORE|AFTER|INSTEAD\s+OF)\s*$`).MatchString(prefix)) ||
		(table == "with" && sqlScopeCode(query)[position] == ' ' && regexp.MustCompile(`(?i)^UPDATE\s+WITH\s+GRANT\s+OPTION\b`).MatchString(query[position:]))
}

// Privilege inspection reads PostgreSQL-owned metadata; this does not grant
// repositories ownership of these catalogs or permission to mutate them.
func postgresMetadataRead(owner, table, query string) bool {
	normalized := strings.TrimPrefix(table, "pg_catalog.")
	metadataOwner := owner == "schemaversion" || ((owner == "compensation" || owner == "notification") && (normalized == "pg_class" || normalized == "pg_namespace" || normalized == "pg_roles")) || (owner == "identity" && (table == "pg_catalog.pg_class" || table == "pg_catalog.pg_namespace"))
	if !metadataOwner {
		return false
	}
	switch normalized {
	case "pg_roles", "pg_auth_members", "pg_namespace", "pg_class", "pg_proc":
	default:
		return false
	}
	if !regexp.MustCompile(`(?i)^SELECT\b`).MatchString(strings.TrimSpace(query)) || strings.Contains(query, ";") || strings.Contains(query, "--") || strings.Contains(query, "/*") || strings.Contains(regexp.MustCompile(`\$[0-9]+`).ReplaceAllString(query, "?"), "$") {
		return false
	}
	// Privilege names inside SQL string literals are data, not statement verbs.
	sanitized := regexp.MustCompile(`'(?:''|[^'])*'`).ReplaceAllString(query, "''")
	return !regexp.MustCompile(`(?i)\b(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|COPY|CALL|DO)\b`).MatchString(sanitized)
}

// executionGenerationTriggerCatalogRead is a narrow exception for the
// idempotent migration probe that reads PostgreSQL's pg_trigger catalog before
// creating four fixed triggers on execution-owned journal tables. It does not
// grant arbitrary pg_trigger reads or writes to the execution module.
func executionGenerationTriggerCatalogRead(owner, table, query string) bool {
	if owner != "execution" || table != "pg_trigger" {
		return false
	}
	normalized := strings.Join(strings.Fields(query), " ")
	if !strings.HasPrefix(normalized, "DO $generation_journal_triggers$ BEGIN ") ||
		!strings.HasSuffix(normalized, " END; $generation_journal_triggers$;") ||
		strings.Count(strings.ToLower(normalized), "from pg_trigger") != 4 ||
		strings.Count(strings.ToLower(normalized), "create trigger") != 4 {
		return false
	}
	guards := []string{
		"IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('platform_execution_generation_claim_journal') AND tgname='platform_generation_claim_no_row_mutation' AND NOT tgisinternal) THEN EXECUTE 'CREATE TRIGGER platform_generation_claim_no_row_mutation BEFORE UPDATE OR DELETE ON platform_execution_generation_claim_journal FOR EACH ROW EXECUTE FUNCTION platform_execution_generation_journal_reject_mutation()'; END IF;",
		"IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('platform_execution_generation_claim_journal') AND tgname='platform_generation_claim_no_truncate' AND NOT tgisinternal) THEN EXECUTE 'CREATE TRIGGER platform_generation_claim_no_truncate BEFORE TRUNCATE ON platform_execution_generation_claim_journal FOR EACH STATEMENT EXECUTE FUNCTION platform_execution_generation_journal_reject_mutation()'; END IF;",
		"IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('platform_execution_generation_dispatch_journal') AND tgname='platform_generation_dispatch_no_row_mutation' AND NOT tgisinternal) THEN EXECUTE 'CREATE TRIGGER platform_generation_dispatch_no_row_mutation BEFORE UPDATE OR DELETE ON platform_execution_generation_dispatch_journal FOR EACH ROW EXECUTE FUNCTION platform_execution_generation_journal_reject_mutation()'; END IF;",
		"IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('platform_execution_generation_dispatch_journal') AND tgname='platform_generation_dispatch_no_truncate' AND NOT tgisinternal) THEN EXECUTE 'CREATE TRIGGER platform_generation_dispatch_no_truncate BEFORE TRUNCATE ON platform_execution_generation_dispatch_journal FOR EACH STATEMENT EXECUTE FUNCTION platform_execution_generation_journal_reject_mutation()'; END IF;",
	}
	for _, guard := range guards {
		if !strings.Contains(normalized, guard) {
			return false
		}
	}
	return true
}

func tableViolations(owner, query string, owners map[string]string) []string {
	var findings []string
	ctes := completedCTEs(query)
	// 授权语句的 ON 对象仍须属于模块，FROM 后的角色不是数据表。
	privileges := regexp.MustCompile("(?i)\\b(?:GRANT|REVOKE)\\s+[^;\"']*?\\bON\\s+(?:TABLE\\s+)?[`\"]?([a-z_][a-z0-9_]*(?:\\.[a-z_][a-z0-9_]*)?)[`\"]?")
	for _, match := range privileges.FindAllStringSubmatch(query, -1) {
		table := strings.ToLower(match[1])
		if expected, ok := owners[table]; !ok || expected != owner {
			findings = append(findings, "foreign/unknown privilege table: "+table)
		}
	}
	for _, match := range tableReference.FindAllStringSubmatchIndex(query, -1) {
		table := strings.ToLower(query[match[2]:match[3]])
		matched := strings.ToUpper(query[match[0]:match[1]])
		operation := strings.Fields(matched)[0]
		if table == "lateral" && strings.HasPrefix(strings.TrimSpace(query[match[1]:]), "(") {
			continue
		}
		if (operation == "FROM" || operation == "JOIN") && cteReadAt(ctes[table], match[0]) {
			continue
		}
		if (table == "jsonb_to_recordset" || table == "pg_catalog.jsonb_to_recordset" || table == "jsonb_populate_record" || table == "aclexplode" || table == "pg_catalog.aclexplode" || table == "jsonb_array_elements" || table == "pg_catalog.jsonb_array_elements") && strings.HasPrefix(strings.TrimSpace(query[match[1]:]), "(") {
			continue
		}
		// REVOKE FROM 后是角色；目标表由源绑定动态登记约束。
		if strings.HasPrefix(matched, "FROM ") && strings.HasPrefix(strings.ToUpper(strings.TrimSpace(query)), "REVOKE ") {
			continue
		}
		// IS [NOT] DISTINCT FROM 是表达式，OLD/NEW 字段不是表。
		if strings.HasPrefix(matched, "FROM ") && (table == "old.effect_stamp" || table == "new.effect_stamp") && regexp.MustCompile(`(?i)\bIS\s+(?:NOT\s+)?DISTINCT\s*$`).MatchString(query[:match[0]]) {
			continue
		}
		if operation == "UPDATE" && nonTableUpdate(query, match[0], table) {
			continue
		}
		if strings.HasPrefix(matched, "FROM ") && (table == "information_schema.tables" || table == "information_schema.columns" || table == "information_schema.statistics") {
			continue
		}
		if postgresMetadataRead(owner, table, query) {
			continue
		}
		if strings.Fields(matched)[0] == "FROM" && executionGenerationTriggerCatalogRead(owner, table, query) {
			continue
		}
		if expected, ok := owners[table]; !ok || expected != owner {
			findings = append(findings, "foreign/unknown table: "+table)
		}
	}
	return findings
}

func validateSQLSite(owner, relative string, source []byte, site sqlSite, owners map[string]string, dynamic map[string]dynamicSQLRegistration) []string {
	findings := tableViolations(owner, site.Text, owners)
	if site.Complete {
		return findings
	}
	key := relative + "#" + site.Function
	registration, ok := dynamic[key]
	sum := sha256.Sum256(source)
	// The migration transaction adapter forwards already-checked repository
	// statements unchanged. Only these two source-bound methods may forward;
	// it receives no table ownership or permission to construct SQL.
	if ok && registration.Forwarding && owner == "sqlutil" && relative == "sqlutil/transaction_db.go" &&
		(site.Function == "transactionConnection.ExecContext" || site.Function == "transactionConnection.QueryContext") &&
		site.Expression == "query" && registration.SourceSHA256 == hex.EncodeToString(sum[:]) &&
		len(registration.Tables) == 0 && strings.TrimSpace(registration.Reason) != "" {
		return findings
	}
	if ok && registration.Forwarding {
		return append(findings, "invalid SQL forwarding registration: "+key)
	}
	if !ok || registration.SourceSHA256 != hex.EncodeToString(sum[:]) || strings.TrimSpace(registration.Reason) == "" || len(registration.Tables) == 0 {
		return append(findings, "unregistered/stale dynamic SQL: "+key)
	}
	for _, table := range registration.Tables {
		if expected, ok := owners[table]; !ok || expected != owner {
			findings = append(findings, "dynamic foreign/unknown table: "+table)
		}
	}
	return findings
}

func TestSQLModuleBoundaries(t *testing.T) {
	_, current, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(current))
	repository := filepath.Dir(filepath.Dir(root))
	read := func(name string, into any) {
		data, err := os.ReadFile(filepath.Join(repository, "contracts", "architecture", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, into); err != nil {
			t.Fatal(err)
		}
	}
	owners := map[string]string{}
	dynamic := map[string]dynamicSQLRegistration{}
	read("table-owners.json", &owners)
	read("dynamic-sql.json", &dynamic)
	// Collect package-level constants, including SQL column lists in sibling files.
	// 解析同包常量，避免跨文件字段清单被误判为任意动态 SQL。
	constants := map[string]map[string]ast.Expr{}
	sources := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".pb.go") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if err != nil {
			return err
		}
		directory := filepath.Dir(path)
		if constants[directory] == nil {
			constants[directory] = map[string]ast.Expr{}
		}
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.CONST {
				continue
			}
			for _, specification := range general.Specs {
				value := specification.(*ast.ValueSpec)
				for i, name := range value.Names {
					if i < len(value.Values) {
						constants[directory][name.Name] = value.Values[i]
					}
				}
			}
		}
		sources[path] = source
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for path, source := range sources {
		relative, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatal(err)
		}
		relative = filepath.ToSlash(relative)
		owner := strings.Split(relative, "/")[0]
		sites, err := sqlSites(source, constants[filepath.Dir(path)])
		if err != nil {
			t.Fatal(err)
		}
		for _, site := range sites {
			for _, finding := range validateSQLSite(owner, relative, source, site, owners, dynamic) {
				t.Error(fmt.Sprintf("%s:%d: %s", relative, site.Line, finding))
			}
		}
	}
}

func TestSQLASTNegativeFixtures(t *testing.T) {
	owners := map[string]string{"platform_audit_event": "audit", "platform_execution_run": "execution"}
	for _, fixture := range []struct {
		name, source string
		allowed      bool
	}{
		{"own", "package x; func f(){ db.Exec(`UPDATE platform_audit_event SET id=?`) }", true},
		{"bound-own", "package x; func f(){db.Exec(sqlutil.Bind(`UPDATE platform_audit_event SET id=?`))}", true},
		{"bound-foreign", "package x; func f(){db.Query(sqlutil.Bind(`SELECT * FROM platform_execution_run`))}", false},
		{"cte-own", "package x; func f(){db.Query(`WITH allowed AS (SELECT * FROM platform_audit_event) SELECT * FROM allowed`)}", true},
		{"cte-foreign", "package x; func f(){db.Query(`WITH allowed AS (SELECT * FROM platform_execution_run) SELECT * FROM allowed`)}", false},
		{"cte-shadow-foreign", "package x; func f(){db.Query(`WITH platform_execution_run AS (SELECT * FROM platform_execution_run) SELECT * FROM platform_execution_run`)}", false},
		{"update-as-alias-foreign", "package x; func f(){db.Exec(`UPDATE platform_execution_run AS r SET status=1`)}", false},
		{"update-bare-alias-foreign", "package x; func f(){db.Exec(`UPDATE platform_execution_run r SET status=1`)}", false},
		{"cte-write-target-foreign", "package x; func f(){db.Exec(`WITH platform_execution_run AS (SELECT * FROM platform_audit_event) UPDATE platform_execution_run SET status=1`)}", false},
		{"cte-inner-scope-foreign", "package x; func f(){db.Query(`WITH own AS (WITH platform_execution_run AS (SELECT * FROM platform_audit_event) SELECT * FROM platform_execution_run) SELECT * FROM platform_execution_run`)}", false},
		{"split-join", "package x; const prefix=`platform_`; func f(){db.Query(`SELECT id FROM `+prefix+`execution_run`) }", false},
		{"unknown", "package x; func f(){db.Exec(`DELETE FROM unknown_table`) }", false},
		{"dynamic", "package x; func f(q string){db.QueryContext(ctx,q) }", false},
		{"prepare-own", "package x; func f(){db.Prepare(`SELECT * FROM platform_audit_event`)}", true},
		{"prepare-foreign", "package x; func f(){db.Prepare(`SELECT * FROM platform_execution_run`)}", false},
		{"prepare-context-foreign", "package x; func f(){db.PrepareContext(ctx,`SELECT * FROM platform_execution_run`)}", false},
		{"prepare-dynamic", "package x; func f(q string){db.Prepare(q)}", false},
		{"prepare-context-dynamic", "package x; func f(q string){db.PrepareContext(ctx,q)}", false},
		{"domain-prepare", "package x; func f(){coordinator.Prepare(ctx,scope,config,false)}", true},
		{"comment", "package x; // db.Exec(`DELETE FROM unknown_table`)\nfunc f(){}", true},
		{"local-split", "package x; func f(){prefix:=`platform_`; table:=prefix+`execution_run`; db.Query(`SELECT id FROM `+table) }", false},
		{"literal-branches", "package x; func f(ok bool){q:=`SELECT id FROM platform_audit_event`; if ok {q=`SELECT id FROM platform_execution_run`}; db.Query(q) }", false},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			sites, err := sqlSites([]byte(fixture.source), nil)
			if err != nil {
				t.Fatal(err)
			}
			var findings []string
			for _, site := range sites {
				findings = append(findings, validateSQLSite("audit", "audit/source.go", []byte(fixture.source), site, owners, nil)...)
			}
			if (len(findings) == 0) != fixture.allowed {
				t.Fatalf("allowed=%v findings=%v", fixture.allowed, findings)
			}
		})
	}
}

func TestDynamicSQLRegistrationIsSourceBound(t *testing.T) {
	source := []byte("package x; func f(q string){ db.Query(q) }")
	sites, err := sqlSites(source, nil)
	if err != nil {
		t.Fatal(err)
	}
	owners := map[string]string{"platform_audit_event": "audit", "platform_execution_run": "execution"}
	sum := sha256.Sum256(source)
	key := "audit/source.go#f"
	entry := dynamicSQLRegistration{SourceSHA256: hex.EncodeToString(sum[:]), Tables: []string{"platform_audit_event"}, Reason: "fixture explicitly reviewed"}
	registry := map[string]dynamicSQLRegistration{key: entry}
	if findings := validateSQLSite("audit", "audit/source.go", source, sites[0], owners, registry); len(findings) != 0 {
		t.Fatal(findings)
	}
	changed := append(append([]byte(nil), source...), []byte("\n// changed")...)
	if findings := validateSQLSite("audit", "audit/source.go", changed, sites[0], owners, registry); len(findings) == 0 {
		t.Fatal("stale source hash accepted")
	}
	entry.Tables = []string{"platform_execution_run"}
	registry[key] = entry
	if findings := validateSQLSite("audit", "audit/source.go", source, sites[0], owners, registry); len(findings) == 0 {
		t.Fatal("foreign dynamic table accepted")
	}
	entry.Tables = []string{"unknown_table"}
	registry[key] = entry
	if findings := validateSQLSite("audit", "audit/source.go", source, sites[0], owners, registry); len(findings) == 0 {
		t.Fatal("unknown dynamic table accepted")
	}
}

func TestTransactionSQLForwardingIsNarrowAndSourceBound(t *testing.T) {
	source := []byte("package sqlutil; type transactionConnection struct{}; func (c transactionConnection) ExecContext(query string){ c.tx.ExecContext(ctx, query) }")
	sites, err := sqlSites(source, nil)
	if err != nil || len(sites) != 1 {
		t.Fatalf("SQL site fixture: %v %+v", err, sites)
	}
	sum := sha256.Sum256(source)
	original := dynamicSQLRegistration{SourceSHA256: hex.EncodeToString(sum[:]), Forwarding: true, Reason: "unchanged transaction forwarding"}
	owners := map[string]string{"platform_audit_event": "audit"}
	for _, test := range []struct {
		name, owner, path, method, expression string
		mutate                                func(*dynamicSQLRegistration)
		accepted                              bool
	}{
		{name: "reviewed adapter", owner: "sqlutil", path: "sqlutil/transaction_db.go", method: "transactionConnection.ExecContext", expression: "query", accepted: true},
		{name: "different owner", owner: "audit", path: "sqlutil/transaction_db.go", method: "transactionConnection.ExecContext", expression: "query"},
		{name: "different file", owner: "sqlutil", path: "sqlutil/other.go", method: "transactionConnection.ExecContext", expression: "query"},
		{name: "different method", owner: "sqlutil", path: "sqlutil/transaction_db.go", method: "makeSQL", expression: "query"},
		{name: "SQL construction", owner: "sqlutil", path: "sqlutil/transaction_db.go", method: "transactionConnection.ExecContext", expression: "query + suffix"},
		{name: "stale source", owner: "sqlutil", path: "sqlutil/transaction_db.go", method: "transactionConnection.ExecContext", expression: "query", mutate: func(r *dynamicSQLRegistration) { r.SourceSHA256 = "stale" }},
		{name: "claims table", owner: "sqlutil", path: "sqlutil/transaction_db.go", method: "transactionConnection.ExecContext", expression: "query", mutate: func(r *dynamicSQLRegistration) { r.Tables = []string{"platform_audit_event"} }},
		{name: "missing review", owner: "sqlutil", path: "sqlutil/transaction_db.go", method: "transactionConnection.ExecContext", expression: "query", mutate: func(r *dynamicSQLRegistration) { r.Reason = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			site := sites[0]
			site.Function = test.method
			site.Expression = test.expression
			entry := original
			if test.mutate != nil {
				test.mutate(&entry)
			}
			registry := map[string]dynamicSQLRegistration{test.path + "#" + test.method: entry}
			findings := validateSQLSite(test.owner, test.path, source, site, owners, registry)
			if (len(findings) == 0) != test.accepted {
				t.Fatalf("SQL forwarding boundary: %v", findings)
			}
			if test.accepted {
				site.Text = "SELECT * FROM platform_audit_event"
				if len(validateSQLSite(test.owner, test.path, source, site, owners, registry)) == 0 {
					t.Fatal("forwarding bypassed foreign table boundary")
				}
			}
		})
	}
}

func TestPostgresCatalogReadsDoNotGrantCatalogOwnership(t *testing.T) {
	owners := map[string]string{}
	for _, query := range []string{"SELECT * FROM pg_catalog.pg_roles", "SELECT has_table_privilege(1,'UPDATE') FROM pg_catalog.pg_roles"} {
		if findings := tableViolations("schemaversion", query, owners); len(findings) != 0 {
			t.Fatal(findings)
		}
		if len(tableViolations("identity", query, owners)) == 0 {
			t.Fatal("metadata exception escaped privilege inspector")
		}
	}
	for _, query := range []string{"UPDATE pg_catalog.pg_roles SET rolsuper=true", "DELETE FROM pg_catalog.pg_roles", "SELECT * FROM pg_catalog.pg_roles; DELETE FROM pg_catalog.pg_roles", "WITH x AS (DELETE FROM pg_catalog.pg_roles RETURNING *) SELECT * FROM x", "SELECT * FROM pg_catalog.pg_authid", "SELECT * FROM platform_identity_principal JOIN pg_catalog.pg_roles ON true"} {
		if len(tableViolations("schemaversion", query, owners)) == 0 {
			t.Fatalf("catalog mutation/foreign table accepted: %s", query)
		}
	}
}

func TestFirstAdministratorCatalogReadRemainsReadOnly(t *testing.T) {
	owners := map[string]string{}
	for _, query := range []string{"SELECT * FROM pg_catalog.pg_class", "SELECT * FROM pg_catalog.pg_namespace"} {
		if len(tableViolations("identity", query, owners)) != 0 {
			t.Fatal("first-administrator catalog read rejected")
		}
	}
	for _, query := range []string{"UPDATE pg_catalog.pg_class SET relowner=1", "DELETE FROM pg_catalog.pg_namespace", "SELECT * FROM pg_catalog.pg_class; DROP TABLE platform_identity_principal", "WITH changed AS (DELETE FROM pg_catalog.pg_class RETURNING *) SELECT * FROM changed", "SELECT * FROM pg_catalog.pg_roles", "SELECT * FROM platform_execution_run JOIN pg_catalog.pg_class ON true"} {
		if len(tableViolations("identity", query, owners)) == 0 {
			t.Fatalf("IAM metadata exception admitted forbidden access: %s", query)
		}
	}
}

func TestExecutionGenerationTriggerCatalogExceptionIsReadOnlyAndExact(t *testing.T) {
	owners := map[string]string{
		"platform_execution_generation_claim_journal":    "execution",
		"platform_execution_generation_dispatch_journal": "execution",
	}
	query := `DO $generation_journal_triggers$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('platform_execution_generation_claim_journal') AND tgname='platform_generation_claim_no_row_mutation' AND NOT tgisinternal) THEN
  EXECUTE 'CREATE TRIGGER platform_generation_claim_no_row_mutation BEFORE UPDATE OR DELETE ON platform_execution_generation_claim_journal FOR EACH ROW EXECUTE FUNCTION platform_execution_generation_journal_reject_mutation()';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('platform_execution_generation_claim_journal') AND tgname='platform_generation_claim_no_truncate' AND NOT tgisinternal) THEN
  EXECUTE 'CREATE TRIGGER platform_generation_claim_no_truncate BEFORE TRUNCATE ON platform_execution_generation_claim_journal FOR EACH STATEMENT EXECUTE FUNCTION platform_execution_generation_journal_reject_mutation()';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('platform_execution_generation_dispatch_journal') AND tgname='platform_generation_dispatch_no_row_mutation' AND NOT tgisinternal) THEN
  EXECUTE 'CREATE TRIGGER platform_generation_dispatch_no_row_mutation BEFORE UPDATE OR DELETE ON platform_execution_generation_dispatch_journal FOR EACH ROW EXECUTE FUNCTION platform_execution_generation_journal_reject_mutation()';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('platform_execution_generation_dispatch_journal') AND tgname='platform_generation_dispatch_no_truncate' AND NOT tgisinternal) THEN
  EXECUTE 'CREATE TRIGGER platform_generation_dispatch_no_truncate BEFORE TRUNCATE ON platform_execution_generation_dispatch_journal FOR EACH STATEMENT EXECUTE FUNCTION platform_execution_generation_journal_reject_mutation()';
 END IF;
END;
$generation_journal_triggers$;`
	if findings := tableViolations("execution", query, owners); len(findings) != 0 {
		t.Fatalf("fixed read-only pg_trigger migration probe rejected: %v", findings)
	}
	for _, fixture := range []struct {
		name, owner, query string
	}{
		{"unrelated-read", "execution", "SELECT * FROM pg_trigger"},
		{"write", "execution", "UPDATE pg_trigger SET tgenabled='D'"},
		{"delete", "execution", "DELETE FROM pg_trigger"},
		{"mutated-probe", "execution", strings.Replace(query, "CREATE TRIGGER platform_generation_claim_no_row_mutation", "CREATE TRIGGER platform_generation_claim_no_row_mutation; DELETE FROM pg_trigger", 1)},
		{"foreign-owner", "capability", query},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			if findings := tableViolations(fixture.owner, fixture.query, owners); len(findings) == 0 {
				t.Fatalf("pg_trigger exception accepted forbidden query: %s", fixture.query)
			}
		})
	}
}

func TestPostgresExpressionsAndPrivilegesDoNotRelaxTableOwnership(t *testing.T) {
	owners := map[string]string{"platform_audit_event": "audit", "platform_execution_run": "execution"}
	for _, tc := range []struct {
		name, owner, query string
		allowed            bool
	}{
		{"lateral-own", "audit", "SELECT * FROM LATERAL (SELECT * FROM platform_audit_event) x", true},
		{"lateral-foreign", "audit", "SELECT * FROM LATERAL (SELECT * FROM platform_execution_run) x", false},
		{"builtin-call", "audit", "SELECT * FROM jsonb_to_recordset('{}') AS x(id text)", true},
		{"builtin-table", "audit", "SELECT * FROM jsonb_to_recordset", false},
		{"unknown-function", "audit", "SELECT * FROM arbitrary_function()", false},
		{"trigger-expression", "audit", "IS NOT DISTINCT FROM OLD.effect_stamp", true},
		{"old-schema-table", "audit", "SELECT * FROM OLD.effect_stamp", false},
		{"own-revoke", "audit", "REVOKE DELETE ON platform_audit_event FROM PUBLIC", true},
		{"foreign-revoke", "audit", "REVOKE DELETE ON platform_execution_run FROM PUBLIC", false},
		{"cte-second-statement", "audit", "WITH platform_execution_run AS (SELECT * FROM platform_audit_event) SELECT * FROM platform_execution_run; SELECT * FROM platform_execution_run", false},
		{"catalog-parameter", "notification", "SELECT rolname FROM pg_roles WHERE oid=$1", true},
		{"catalog-mutating", "notification", "DELETE FROM pg_roles", false},
		{"catalog-business-owner", "audit", "SELECT * FROM pg_roles", false},
		{"catalog-foreign-join", "notification", "SELECT * FROM pg_roles JOIN platform_execution_run ON true", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings := tableViolations(tc.owner, tc.query, owners)
			if (len(findings) == 0) != tc.allowed {
				t.Fatalf("allowed=%v findings=%v", tc.allowed, findings)
			}
		})
	}
}

func TestUpdateAliasesAndCTEScopesPreserveTableOwnership(t *testing.T) {
	owners := map[string]string{"platform_audit_event": "audit", "platform_execution_run": "execution"}
	for _, tc := range []struct {
		name, query string
		allowed     bool
	}{
		{"update-as-foreign", "UPDATE platform_execution_run AS r SET status=1", false},
		{"update-bare-foreign", "UPDATE platform_execution_run r SET status=1", false},
		{"update-own", "UPDATE platform_audit_event AS e SET id=1", true},
		{"cte-update-target", "WITH platform_execution_run AS (SELECT * FROM platform_audit_event) UPDATE platform_execution_run SET status=1", false},
		{"cte-insert-target", "WITH platform_execution_run AS (SELECT * FROM platform_audit_event) INSERT INTO platform_execution_run SELECT * FROM platform_execution_run", false},
		{"cte-delete-target", "WITH platform_execution_run AS (SELECT * FROM platform_audit_event) DELETE FROM platform_execution_run", false},
		{"nested-cte-escape", "WITH own AS (WITH platform_execution_run AS (SELECT * FROM platform_audit_event) SELECT * FROM platform_execution_run) SELECT * FROM platform_execution_run", false},
		{"nested-cte-own", "WITH own AS (WITH platform_execution_run AS (SELECT * FROM platform_audit_event) SELECT * FROM platform_execution_run) SELECT * FROM own", true},
		{"literal-fake-cte", "SELECT 'WITH platform_execution_run AS (SELECT 1)' label FROM platform_execution_run", false},
		{"comment-fake-cte", "SELECT 1 /* WITH platform_execution_run AS (SELECT 1) */ FROM platform_execution_run", false},
		{"dollar-literal-fake-cte", "SELECT $note$WITH platform_execution_run AS (SELECT 1)$note$ FROM platform_execution_run", false},
		{"quoted-cte-punctuation", "WITH own AS (SELECT ');' label FROM platform_audit_event) SELECT * FROM own", true},
		{"lock-skip", "SELECT * FROM platform_audit_event FOR UPDATE SKIP LOCKED", true},
		{"lock-of", "SELECT * FROM platform_audit_event e FOR UPDATE OF e", true},
		{"lock-no-key", "SELECT * FROM platform_audit_event FOR NO KEY UPDATE NOWAIT", true},
		{"upsert-own", "INSERT INTO platform_audit_event(id) VALUES (1) ON CONFLICT(id) DO UPDATE SET id=1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings := tableViolations("audit", tc.query, owners)
			if (len(findings) == 0) != tc.allowed {
				t.Fatalf("allowed=%v findings=%v", tc.allowed, findings)
			}
		})
	}
}
