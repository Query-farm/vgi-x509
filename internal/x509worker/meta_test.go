// Copyright 2026 Query Farm LLC - https://query.farm

package x509worker

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Query-farm/vgi-go/vgi"
)

// exampleListLimit is the vgi-lint VGI417 bound on a vgi.example_queries tag
// (vgi-lint-check >= 2.5.1). Other tags stay at 4,000.
const exampleListLimit = 8000

func TestExampleListsWithinAgentLimit(t *testing.T) {
	lists := map[string]string{"schema main": SchemaExampleQueries}
	for _, f := range scalarFunctions() {
		lists[f.Name()] = f.Metadata().Tags["vgi.example_queries"]
	}
	lists["cert_info"] = (&certInfoFunc{}).Metadata().Tags["vgi.example_queries"]
	lists["tls_inspect"] = (&tlsInspectFunc{}).Metadata().Tags["vgi.example_queries"]
	for name, v := range lists {
		if v == "" {
			t.Errorf("%s: no vgi.example_queries", name)
			continue
		}
		if len(v) > exampleListLimit {
			t.Errorf("%s: vgi.example_queries is %d chars, limit %d", name, len(v), exampleListLimit)
		}
		var exs []executableExample
		if err := json.Unmarshal([]byte(v), &exs); err != nil {
			t.Errorf("%s: not a JSON example list: %v", name, err)
		}
		for i, e := range exs {
			if strings.TrimSpace(e.Description) == "" || strings.TrimSpace(e.SQL) == "" {
				t.Errorf("%s: example %d lacks a description or SQL", name, i)
			}
		}
	}
}

// The vgi-lint agent simulator shows agents only the first five examples of
// each object, never the schema-level list, so each composed example must be
// within the first five of the object that drives it.
func TestComposedExamplesOnDrivingObjects(t *testing.T) {
	examples := map[string][]vgi.CatalogExample{}
	for _, f := range scalarFunctions() {
		examples[f.Name()] = f.Metadata().Examples
	}
	examples["tls_inspect"] = (&tlsInspectFunc{}).Metadata().Examples
	want := map[string][]vgi.CatalogExample{
		"cert_not_after":           {ComposedPolicyAuditExample},
		"cert_key_algorithm":       {ComposedPolicyAuditExample},
		"cert_signature_algorithm": {ComposedPolicyAuditExample},
		"cert_sans":                {ComposedHostCoverageExample},
		"cert_is_expired":          {ComposedHostCoverageExample},
		"tls_inspect":              {ComposedLiveInventoryExample},
	}
	for fn, composed := range want {
		got := examples[fn]
		if len(got) > 5 {
			got = got[:5]
		}
		for _, c := range composed {
			found := false
			for _, e := range got {
				if e.SQL == c.SQL {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: composed example %q not within its first five examples", fn, c.Description[:40])
			}
		}
	}
	for _, c := range []vgi.CatalogExample{ComposedPolicyAuditExample, ComposedHostCoverageExample} {
		if !strings.Contains(SchemaExampleQueries, mustJSON(c.SQL)[1:40]) {
			t.Errorf("schema example list lacks composed example %q", c.Description[:40])
		}
	}
}

// Every published task name must have exactly one grader in the private
// sidecar, and vice versa.
func TestAgentTasksMatchSidecar(t *testing.T) {
	var tasks []agentTestTask
	if err := json.Unmarshal([]byte(AgentTestTasksJSON), &tasks); err != nil {
		t.Fatal(err)
	}
	var published []string
	for _, task := range tasks {
		published = append(published, task.Name)
	}
	raw, err := os.ReadFile("../../vgi-agent-tests.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var graded []string
	for _, m := range regexp.MustCompile(`(?m)^  - name: "([^"]+)"$`).FindAllStringSubmatch(string(raw), -1) {
		graded = append(graded, m[1])
	}
	sort.Strings(published)
	sort.Strings(graded)
	if strings.Join(published, "|") != strings.Join(graded, "|") {
		t.Errorf("task names differ\npublished: %q\ngraded:    %q", published, graded)
	}
}
