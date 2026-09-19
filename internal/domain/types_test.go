package domain

import (
	"encoding/json"
	"testing"
	"time"
)

func TestOptionalTimesJSONContract(t *testing.T) {
	timestamp := time.Date(2026, time.September, 19, 12, 34, 56, 0, time.UTC)
	tests := []struct {
		name      string
		zero      any
		populated any
		key       string
	}{
		{name: "MCP tool call", zero: MCPToolCall{Status: "running"}, populated: MCPToolCall{Status: "completed", CompletedAt: timestamp}, key: "completed_at"},
		{name: "chat tool call", zero: ChatToolCall{Status: "running"}, populated: ChatToolCall{Status: "completed", CompletedAt: timestamp}, key: "completed_at"},
		{name: "execution result", zero: ExecResult{Status: "running"}, populated: ExecResult{Status: "completed", CompletedAt: timestamp}, key: "completed_at"},
		{name: "SSH shell", zero: SSHShell{Status: "running"}, populated: SSHShell{Status: "exited", EndedAt: timestamp}, key: "ended_at"},
		{name: "run", zero: Run{Status: "running"}, populated: Run{Status: "completed", CompletedAt: timestamp}, key: "completed_at"},
		{name: "run search page", zero: RunSearchPage{}, populated: RunSearchPage{NextStartedAt: timestamp}, key: "next_started_at"},
		{name: "approval", zero: Approval{Status: "pending"}, populated: Approval{Status: "approved", DecidedAt: timestamp}, key: "decided_at"},
		{name: "task", zero: Task{Status: "running"}, populated: Task{Status: "completed", EndedAt: timestamp}, key: "ended_at"},
		{name: "audit event page", zero: AuditEventPage{}, populated: AuditEventPage{NextCreatedAt: timestamp}, key: "next_created_at"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(test.zero)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			if _, exists := fields[test.key]; exists {
				t.Fatalf("zero %s was serialized: %s", test.key, encoded)
			}

			encoded, err = json.Marshal(test.populated)
			if err != nil {
				t.Fatal(err)
			}
			fields = nil
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			if got := fields[test.key]; got != timestamp.Format(time.RFC3339Nano) {
				t.Fatalf("populated %s = %#v, want %q in %s", test.key, got, timestamp.Format(time.RFC3339Nano), encoded)
			}
		})
	}
}

func TestDefaultWorkspaceShellModeUsesHostOutsideLinux(t *testing.T) {
	tests := map[string]string{
		"linux":   WorkspaceShellModeSandbox,
		"windows": WorkspaceShellModeHost,
		"darwin":  WorkspaceShellModeHost,
	}
	for goos, expected := range tests {
		if actual := DefaultWorkspaceShellMode(goos); actual != expected {
			t.Fatalf("default Workspace Shell mode for %s = %q, want %q", goos, actual, expected)
		}
	}
}
