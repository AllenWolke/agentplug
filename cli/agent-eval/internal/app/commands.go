package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lexagent/agent-eval/internal/client"
	agenteval "github.com/lexagent/agent-evaluation"
	"golang.org/x/term"
)

type stringsFlag []string

func (s *stringsFlag) String() string { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error {
	if !safeID.MatchString(v) {
		return errors.New("invalid identifier")
	}
	*s = append(*s, v)
	return nil
}

func Main(ctx context.Context, args []string, in *os.File, out, errOut io.Writer) error {
	lineReader := bufio.NewReader(in)
	command := "interactive"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command, args = args[0], args[1:]
	}
	if command == "fixture" {
		return Fixture(ctx, args, out)
	}
	if command == "judge" {
		return Service(ctx, "judge", args, out)
	}
	if command == "help" || command == "version" {
		if command == "version" {
			fmt.Fprintln(out, "agent-eval 0.1.0")
			return nil
		}
		fmt.Fprintln(out, usage)
		return nil
	}
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(errOut)
	base := f.String("platform", "http://127.0.0.1:38080", "public platform gateway origin")
	credentialsPath := f.String("credentials-file", "", "read-only JSON with username/password; never recorded")
	workspaceFlag := f.String("workspace", "", "tenant/department/application workspace")
	configPath := f.String("config", "", "versioned evaluation config")
	dir := f.String("out", "agent-eval-results", "private report directory")
	id := f.String("id", "", "stable batch/resource identifier")
	input := f.String("input", "", "report/trial JSON file")
	expectedPath := f.String("expected", "", "reviewed expected assertions JSON")
	kind := f.String("kind", "evidence", "review/publish resource: datasets, metrics or evidence")
	decision := f.String("decision", "", "approved, rejected or needs_changes")
	reason := f.String("reason", "", "human review reason")
	rubricPath := f.String("rubric", "", "versioned model-review rubric JSON")
	limitTokens := f.Int64("limit-tokens", 0, "explicit total judging token budget")
	limitMicros := f.Int64("limit-micros", -1, "explicit total judging cost budget")
	baseline := f.String("baseline", "", "baseline report JSON")
	candidate := f.String("candidate", "", "candidate report JSON")
	var agents, runs, judgeRuns, feedbackIDs stringsFlag
	f.Var(&agents, "agent", "selected installation id; repeat for multi-select")
	f.Var(&runs, "run", "execution Run id; repeat for analysis")
	f.Var(&judgeRuns, "judgement-run", "authorized grading execution Run id; repeat")
	f.Var(&feedbackIDs, "feedback", "platform human feedback id; repeat")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	switch command {
	case "metrics":
		for _, d := range agenteval.Definitions() {
			fmt.Fprintf(out, "%s\t%s\t%s\t%s\n", d.ID, d.Dimension, d.Unit, d.Description)
		}
		return nil
	case "rubric-hash":
		var rubric agenteval.Rubric
		if e := readJSON(*input, &rubric); e != nil {
			return e
		}
		fmt.Fprintln(out, agenteval.RubricDigest(rubric))
		return nil
	case "report":
		var r agenteval.Report
		if e := readJSON(*input, &r); e != nil {
			return e
		}
		if r.Version != agenteval.ReportVersion {
			return errors.New("unsupported report")
		}
		fmt.Fprint(out, agenteval.Markdown(r))
		return nil
	case "compare":
		return Compare(*baseline, *candidate, out)
	case "analyze":
		if *input != "" {
			var trials []agenteval.Trial
			if e := readJSON(*input, &trials); e != nil {
				return e
			}
			for i := range trials {
				trials[i].Trajectory.Source = "imported"
			}
			if e := os.MkdirAll(*dir, 0700); e != nil {
				return e
			}
			r := agenteval.Score(trials)
			if e := saveReport(*dir, "analysis", r); e != nil {
				return e
			}
			printSummary(out, r)
			return nil
		}
	case "interactive", "discover", "init", "run", "prepare", "bind", "review", "publish", "cancel", "model-prepare":
	default:
		return errors.New("unknown command; use agent-eval help")
	}
	c, e := client.New(*base)
	if e != nil {
		return e
	}
	var credentials client.Credentials
	if *credentialsPath != "" {
		if e = readJSON(*credentialsPath, &credentials); e != nil {
			return e
		}
	} else {
		if !term.IsTerminal(int(in.Fd())) {
			return errors.New("noninteractive authentication requires --credentials-file")
		}
		fmt.Fprint(out, "账号：")
		name, e := lineReader.ReadString('\n')
		if e != nil {
			return e
		}
		credentials.Username = strings.TrimSpace(name)
		fmt.Fprint(out, "密码（隐藏输入）：")
		password, e := term.ReadPassword(int(in.Fd()))
		fmt.Fprintln(out)
		if e != nil {
			return e
		}
		credentials.Password = string(password)
		for i := range password {
			password[i] = 0
		}
	}
	if credentials.Username == "" || credentials.Password == "" {
		return errors.New("credentials are required")
	}
	if e = c.Login(ctx, credentials); e != nil {
		return e
	}
	credentials.Password = ""
	defer func() {
		logout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c.Logout(logout)
	}()
	var cfg Config
	if *configPath != "" {
		cfg, e = LoadConfig(*configPath)
		if e != nil {
			return e
		}
		if cfg.Workspace != nil {
			if e = c.Switch(ctx, *cfg.Workspace); e != nil {
				return e
			}
		}
	}
	if *workspaceFlag != "" {
		parts := strings.Split(*workspaceFlag, "/")
		if len(parts) != 3 || !safeID.MatchString(parts[0]) || !safeID.MatchString(parts[1]) || !safeID.MatchString(parts[2]) {
			return errors.New("workspace must be tenant/department/application")
		}
		w := client.Workspace{TenantID: parts[0], DepartmentID: parts[1], ApplicationID: parts[2]}
		if cfg.Workspace != nil && *cfg.Workspace != w {
			return errors.New("workspace differs from the frozen configuration")
		}
		if e = c.Switch(ctx, w); e != nil {
			return e
		}
		cfg.Workspace = &w
	}
	if command == "interactive" || command == "discover" || command == "init" {
		if (command == "interactive" || command == "init") && cfg.Workspace == nil {
			workspaces, e := c.Workspaces(ctx)
			if e != nil {
				return e
			}
			if len(workspaces) == 0 {
				return errors.New("no authorized application workspaces")
			}
			selectedWorkspace := workspaces[0]
			if len(workspaces) > 1 {
				if command == "init" {
					return errors.New("multiple workspaces; use --workspace tenant/department/application")
				}
				for i, w := range workspaces {
					fmt.Fprintf(out, "%d. %s/%s/%s\n", i+1, w.TenantID, w.DepartmentID, w.ApplicationID)
				}
				fmt.Fprint(out, "选择工作空间序号：")
				line, e := lineReader.ReadString('\n')
				if e != nil {
					return e
				}
				n, e := strconv.Atoi(strings.TrimSpace(line))
				if e != nil || n < 1 || n > len(workspaces) {
					return errors.New("invalid workspace selection")
				}
				selectedWorkspace = workspaces[n-1]
			}
			if e = c.Switch(ctx, selectedWorkspace); e != nil {
				return e
			}
			cfg.Workspace = &selectedWorkspace
		}
		found, e := c.Discover(ctx)
		if e != nil {
			return e
		}
		printDiscovery(out, found)
		if command == "discover" {
			return nil
		}
		if command == "init" {
			return InitConfig(found.Items, agents, *dir, out, cfg.Workspace)
		}
		if found.Evaluable == 0 {
			fmt.Fprintln(out, "没有可评估的在线Agent：检查发布、最新部署健康和evaluation.run / 实例run授权。")
			return nil
		}
		fmt.Fprint(out, "选择序号（逗号分隔，或all）：")
		line, e := lineReader.ReadString('\n')
		if e != nil {
			return e
		}
		selected, e := Select(found.Items, strings.TrimSpace(line))
		if e != nil {
			return e
		}
		agents = selected
		if *configPath == "" {
			return InitConfig(found.Items, agents, *dir, out, cfg.Workspace)
		}
		command = "run"
	}
	switch command {
	case "model-prepare":
		if len(agents) != 1 || len(runs) == 0 || *rubricPath == "" || cfg.Workspace == nil || *limitTokens <= 0 || *limitMicros < 0 {
			return errors.New("model-prepare requires explicit workspace, one grading installation, source Runs, rubric and budgets")
		}
		var rubric agenteval.Rubric
		if e := readJSON(*rubricPath, &rubric); e != nil {
			return e
		}
		var expected agenteval.Expected
		if *expectedPath != "" {
			if e := readJSON(*expectedPath, &expected); e != nil {
				return e
			}
		}
		return PrepareModelReview(ctx, c, agents[0], runs, rubric, expected, Budget{LimitTokens: *limitTokens, LimitMicros: *limitMicros}, cfg.Workspace, *dir, out)
	case "run":
		if *configPath == "" {
			return errors.New("--config is required")
		}
		if *id == "" {
			return errors.New("--id is required for durable idempotency and reconnect")
		}
		return Run(ctx, c, cfg, *id, *dir, agents, out)
	case "prepare":
		if *configPath == "" {
			return errors.New("--config is required")
		}
		return Prepare(ctx, c, cfg, *dir, out)
	case "bind":
		if *configPath == "" {
			return errors.New("--config is required")
		}
		return Bind(ctx, c, cfg, *dir, out)
	case "analyze":
		if len(runs) == 0 {
			return errors.New("--run or --input is required")
		}
		var expected agenteval.Expected
		if *expectedPath != "" {
			if e = readJSON(*expectedPath, &expected); e != nil {
				return e
			}
		}
		trials := []agenteval.Trial{}
		for i, run := range runs {
			t, e := c.Trajectory(ctx, run)
			if e != nil {
				return e
			}
			trials = append(trials, agenteval.Trial{CaseID: "historical-" + strconv.Itoa(i+1), Attempt: 1, Trajectory: t, Expected: expected})
		}
		if e = AttachReviews(ctx, c, trials, judgeRuns, feedbackIDs); e != nil {
			return e
		}
		for _, trial := range trials {
			if trial.Trajectory.Agent.AgentID != trials[0].Trajectory.Agent.AgentID || trial.Trajectory.Agent.VersionID != trials[0].Trajectory.Agent.VersionID {
				return errors.New("analyze one Agent version per report; compare separate version cohorts")
			}
		}
		r := agenteval.Score(trials)
		r.Cohort = historicalCohort(trials, expected)
		if r.Cohort != nil {
			r.Cohort.ReviewProtocolHash = reviewProtocolHash(r)
		}
		r.Warnings = append(r.Warnings, "历史运行分析未控制缓存、负载或并发；版本比较仅适用于相同业务输入与金标，不推断性能因果关系")
		if e = os.MkdirAll(*dir, 0700); e != nil {
			return e
		}
		if e = saveReport(*dir, "analysis", r); e != nil {
			return e
		}
		printSummary(out, r)
		return nil
	case "cancel":
		if !safeID.MatchString(*id) {
			return errors.New("--id product evaluation Run required")
		}
		r, e := c.GetResource(ctx, "runs", *id)
		if e != nil {
			return e
		}
		var response client.Resource
		if e = c.Do(ctx, "POST", "/api/modules/evaluation-product/runs/"+*id+"/cancel", map[string]any{"expected_revision": r.Revision}, &response); e != nil {
			return e
		}
		fmt.Fprintf(out, "评测Run %s：%s；停止状态以平台及子Run确认记录为准。\n", response.ID, response.Status)
		return nil
	case "review":
		if *kind == "feedback" {
			var feedback any
			if e := readJSON(*input, &feedback); e != nil {
				return e
			}
			var response client.Resource
			if e := c.Do(ctx, "POST", "/api/modules/evaluation-product/feedback", feedback, &response); e != nil {
				return e
			}
			fmt.Fprintln(out, "人工反馈已记录："+response.ID)
			return nil
		}
		if !safeID.MatchString(*id) || len(strings.TrimSpace(*reason)) < 2 || (*decision != "approved" && *decision != "rejected" && *decision != "needs_changes") {
			return errors.New("review requires id, decision and reason")
		}
		if *kind == "evidence" {
			return c.Do(ctx, "POST", "/api/modules/evaluation-product/reviews", map[string]any{"evidence_id": *id, "decision": *decision, "reason": *reason}, nil)
		}
		if *kind != "datasets" {
			return errors.New("only datasets or evidence can be reviewed")
		}
		r, e := c.GetResource(ctx, *kind, *id)
		if e != nil {
			return e
		}
		return c.Do(ctx, "POST", "/api/modules/evaluation-product/datasets/"+*id+"/review", map[string]any{"expected_revision": r.Revision, "decision": *decision, "reason": *reason}, nil)
	case "publish":
		if (*kind != "datasets" && *kind != "metrics") || !safeID.MatchString(*id) {
			return errors.New("publish requires dataset or metric id")
		}
		r, e := c.GetResource(ctx, *kind, *id)
		if e != nil {
			return e
		}
		return c.Do(ctx, "POST", "/api/modules/evaluation-product/"+*kind+"/"+*id+"/publish", map[string]any{"expected_revision": r.Revision}, nil)
	}
	return nil
}

func Select(items []agenteval.Agent, line string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	if line == "all" {
		for _, a := range items {
			if a.CanEvaluate && a.Health == "online" {
				out = append(out, a.InstallationID)
			}
		}
		return out, nil
	}
	for _, raw := range strings.Split(line, ",") {
		n, e := strconv.Atoi(strings.TrimSpace(raw))
		if e != nil || n < 1 || n > len(items) {
			return nil, errors.New("invalid agent selection")
		}
		a := items[n-1]
		if !a.CanEvaluate || a.Health != "online" {
			return nil, errors.New("selected agent is offline or evaluation is forbidden")
		}
		if !seen[a.InstallationID] {
			out = append(out, a.InstallationID)
			seen[a.InstallationID] = true
		}
	}
	return out, nil
}
func printDiscovery(out io.Writer, d agenteval.Discovery) {
	fmt.Fprintf(out, "在线Agent：%d；在线安装实例：%d；可评估：%d；可见实例：%d\n", d.OnlineAgents, d.OnlineInstances, d.Evaluable, d.Total)
	for i, a := range d.Items {
		active := "不可读取"
		if a.ActiveRuns != nil {
			active = strconv.Itoa(*a.ActiveRuns)
		}
		fmt.Fprintf(out, "%d. %s [%s] %s · %s · %s · 可评估=%t · 本人活跃Run=%s\n", i+1, a.Name, a.Language, a.SemanticVersion, a.InstallationID, a.Health, a.CanEvaluate, active)
		if a.Reason != "" {
			fmt.Fprintln(out, "   原因："+a.Reason)
		}
	}
}
func printSummary(out io.Writer, r agenteval.Report) {
	fmt.Fprintf(out, "样本=%d，安全=%s，任务与安全=%s，建议=%d\n", r.Trials, r.SafetyGate, r.QualityGate, len(r.Recommendations))
	dims := map[string]int{}
	for _, m := range r.Metrics {
		if m.Status == "measured" {
			dims[m.Dimension]++
		}
	}
	keys := []string{}
	for k := range dims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(out, "%s：%d项有测量证据\n", k, dims[k])
	}
}

func Prepare(ctx context.Context, c *client.Client, cfg Config, dir string, out io.Writer) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	for i := range cfg.Targets {
		t := &cfg.Targets[i]
		if t.DatasetID == "" {
			source := cfg.DatasetSource
			if source == "" {
				source = "manual_gold"
			}
			var r client.Resource
			e := c.Do(ctx, "POST", "/api/modules/evaluation-product/datasets", map[string]any{"name": "agent-eval-" + t.AgentID, "version": "1.0.0", "source_type": source, "cases": t.Cases}, &r)
			if e != nil {
				return e
			}
			t.DatasetID = r.ID
			fmt.Fprintf(out, "数据集 %s：draft，需另一位有权限的审核者review后publish。\n", r.ID)
			if e = writeJSON(filepath.Join(dir, "prepared.json"), cfg); e != nil {
				return e
			}
		}
		if t.MetricID == "" {
			r, e := ensureAssertionMetric(ctx, c)
			if e != nil {
				return e
			}
			t.MetricID = r.ID
			fmt.Fprintf(out, "指标 %s：draft，需有权限的审核者publish。\n", r.ID)
			if e = writeJSON(filepath.Join(dir, "prepared.json"), cfg); e != nil {
				return e
			}
		}
	}
	return nil
}
func ensureAssertionMetric(ctx context.Context, c *client.Client) (client.Resource, error) {
	r, e := c.GetResource(ctx, "metrics", "agent-assertions.1.0.0")
	if e != nil {
		var rejected *client.Error
		if !errors.As(e, &rejected) || rejected.Status != 404 {
			return r, e
		}
		e = c.Do(ctx, "POST", "/api/modules/evaluation-product/metrics", map[string]any{"metric_id": "agent-assertions", "version": "1.0.0", "name": "Reviewed business assertions", "kind": "agent_assertions", "formula": map[string]any{}}, &r)
		if e != nil {
			return r, e
		}
	}
	var data struct {
		Kind     string         `json:"kind"`
		PluginID string         `json:"plugin_id"`
		Formula  map[string]any `json:"formula"`
	}
	if json.Unmarshal(r.Data, &data) != nil || data.Kind != "agent_assertions" || data.PluginID != "" || data.Formula == nil || len(data.Formula) != 0 {
		return r, errors.New("existing agent-assertions metric has another definition; use a new reviewed metric identifier")
	}
	return r, nil
}

func Bind(ctx context.Context, c *client.Client, cfg Config, dir string, out io.Writer) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	for i := range cfg.Targets {
		t := &cfg.Targets[i]
		if t.SuiteID != "" {
			continue
		}
		if !safeID.MatchString(t.DatasetID) || !safeID.MatchString(t.MetricID) {
			return errors.New("prepared dataset and metric ids required")
		}
		var r client.Resource
		e := c.Do(ctx, "POST", "/api/modules/evaluation-product/suites", map[string]any{"name": "agent-eval-" + t.AgentID, "version": "1.0.0", "dataset_id": t.DatasetID, "agent_id": t.AgentID, "agent_version_id": t.VersionID, "installation_id": t.InstallationID, "installation_revision": t.Revision, "metric_ids": []string{t.MetricID}}, &r)
		if e != nil {
			return e
		}
		t.SuiteID = r.ID
		fmt.Fprintf(out, "冻结评测套件：%s\n", r.ID)
		if e = writeJSON(filepath.Join(dir, "bound.json"), cfg); e != nil {
			return e
		}
	}
	return nil
}

func Compare(baseline, candidate string, out io.Writer) error {
	var a, b agenteval.Report
	if e := readJSON(baseline, &a); e != nil {
		return e
	}
	if e := readJSON(candidate, &b); e != nil {
		return e
	}
	if a.Version != agenteval.ReportVersion || b.Version != a.Version {
		return errors.New("report versions differ")
	}
	if a.Cohort == nil || b.Cohort == nil || a.Cohort.AgentID == "" || a.Cohort.DatasetHash == "" || checksum(a.Cohort) != checksum(b.Cohort) {
		return errors.New("INCOMPARABLE_COHORT: gold, workload, mode, measurement conditions, currency, thresholds and review protocol must match")
	}
	metrics := map[string]agenteval.Metric{}
	for _, m := range a.Metrics {
		metrics[m.ID] = m
	}
	fmt.Fprintln(out, "指标\t基线\t候选\t变化\t说明")
	for _, m := range b.Metrics {
		if a.Cohort.MeasurementProtocol == "historical-read/v1" && m.Dimension == "cost_latency" {
			fmt.Fprintln(out, m.ID, "不可做受控性能比较：历史运行的并发、缓存和负载未知")
			continue
		}
		if (m.ID == "model_cost" || m.ID == "tool_cost") && (a.Cohort.Currency == "" || a.Cohort.Currency == "mixed") {
			fmt.Fprintln(out, m.ID, "不可比较：没有可核验的统一币种")
			continue
		}
		old, ok := metrics[m.ID]
		if !ok || old.Value == nil || m.Value == nil || old.Unit != m.Unit || old.Status != "measured" || m.Status != "measured" {
			fmt.Fprintln(out, m.ID, "不可比较：证据、单位或样本不足")
			continue
		}
		fmt.Fprintf(out, "%s\t%.4f\t%.4f\t%+.4f\t%s；样本%d/%d\n", m.ID, *old.Value, *m.Value, *m.Value-*old.Value, m.Direction, old.Samples, m.Samples)
	}
	fmt.Fprintln(out, "比较不自动批准发布；需确认用例、工作负载、缓存冷热、币种和并发相同。")
	return nil
}

const usage = `agent-eval — 独立CLI Agent Evaluation
Commands: discover, init, prepare, model-prepare, rubric-hash, metrics, review, publish, bind, run, analyze, compare, report, cancel, fixture, judge
No command: authenticate, discover online agents, single/multi select.
Remote commands: --platform <gateway-origin> --credentials-file <private.json>
run: --config <bound.json> --id <stable-batch> [--agent <installation> ...] --out <private-dir>
analyze: --run <execution-run> ... [--expected <gold.json>] OR --input <imported-trials.json>
compare: --baseline <report.json> --candidate <report.json>
fixture serve: --listen <host:port> --scenario <success|failure|timeout|unknown|selectable>
fixture agent serve / judge serve: optional registered execution-v2 servers
fixture agent bundle / judge bundle: --out <directory> exports manifest and input/output schemas
model-prepare: --workspace <scope> --agent <grading-installation> --run <source> ... --rubric <rubric.json> --limit-tokens <n> --limit-micros <n>
analyze: [--judgement-run <grading-execution> ...] [--feedback <platform-feedback-id> ...]
review --kind feedback --input <feedback.json>: authenticated evidence-backed human calibration
Passwords and tokens are never command arguments or report content.`
