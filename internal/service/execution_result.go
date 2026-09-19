package service

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
)

func execResultFromRun(run domain.Run, approvalID, operatorInstruction string) domain.ExecResult {
	stderr := run.StderrRedacted
	if stderr == "" && run.Error != "" {
		stderr = run.Error
	}
	duration := time.Duration(0)
	if !run.CompletedAt.IsZero() {
		duration = run.CompletedAt.Sub(run.StartedAt)
	}
	result := domain.ExecResult{
		RunID: run.ID, Status: run.Status, ApprovalID: approvalID,
		AutoApproved:        autoApprovedRun(run),
		OperatorInstruction: operatorInstruction, ExitCode: run.ExitCode,
		Stdout: run.StdoutRedacted, Stderr: stderr,
		Duration: duration, CompletedAt: run.CompletedAt,
	}
	var request domain.ExecRequest
	if json.Unmarshal([]byte(run.RequestJSON), &request) == nil && request.Mode == domain.ExecSSHTunnelStart {
		var tunnel domain.SSHTunnel
		if json.Unmarshal([]byte(run.StdoutRedacted), &tunnel) == nil && tunnel.ID != "" {
			result.Tunnel = &tunnel
		}
	}
	if request.Mode == domain.ExecSSHShellStart || request.Mode == domain.ExecWorkspaceShellStart {
		var shell domain.SSHShell
		if json.Unmarshal([]byte(run.StdoutRedacted), &shell) == nil && shell.ID != "" {
			result.Shell = &shell
		}
		result.ShellUsage = sshShellUsage()
	}
	return result
}

func autoApprovedRun(run domain.Run) bool {
	return run.AIReview != nil && run.AIReview.Kind == domain.CommandReviewKindAutomaticApproval && run.AIReview.Status == "completed" && run.AIReview.Decision == domain.ApprovalAgentAllow
}

func executionResult(run domain.Run, req domain.ExecRequest, output executionOutput) domain.ExecResult {
	result := domain.ExecResult{
		RunID: run.ID, Status: run.Status, AutoApproved: autoApprovedRun(run), ExitCode: run.ExitCode,
		Stdout: run.StdoutRedacted, Stderr: run.StderrRedacted,
		Duration: output.raw.Duration, Change: req.Change, Tunnel: output.tunnel, CompletedAt: run.CompletedAt,
		Shell: output.shell,
	}
	if result.Stderr == "" && run.Error != "" {
		result.Stderr = run.Error
	}
	if (req.Mode == domain.ExecSSHShellStart || req.Mode == domain.ExecWorkspaceShellStart) && run.Status == "completed" {
		result.ShellUsage = sshShellUsage()
	}
	if run.Status == "completed" && (req.Mode == domain.ExecRemoteSearch || req.Mode == domain.ExecWorkspaceSearch) {
		decorateFileSearchResult(&result, req.SearchPattern, req.SearchMatchMode, req.ContextLines)
	}
	if run.Status == "completed" && (req.Mode == domain.ExecRemoteRead || req.Mode == domain.ExecWorkspaceRead) && result.Stdout != "" {
		path := req.RemotePath
		if req.Mode == domain.ExecWorkspaceRead {
			path = req.RelativePath
		}
		metadata, content := parseFileReadOutput(path, result.Stdout)
		if req.Mode == domain.ExecRemoteRead || req.TailLines == 0 {
			metadata.OffsetBytes = resolvedFileOffset(metadata.Size, req.OffsetBytes)
		}
		metadata.ReturnedBytes = len(content)
		decorateFileReadPage(&metadata, req.MaxBytes, req.TailLines)
		metadata.Sensitive = strings.Contains(content, "[REDACTED]")
		result.File, result.Stdout = &metadata, content
	}
	if req.Mode == domain.ExecRemoteRead && req.MetadataOnly {
		result.Stdout = ""
	}
	if req.Change != nil {
		path := req.RemotePath
		if req.Mode == domain.ExecWorkspaceEdit {
			path = req.RelativePath
		}
		metadata := parseFileEditOutput(path, req.Validator, result.Stdout, run.Status == "completed")
		result.File = &metadata
	}
	if req.Mode == domain.ExecWorkspaceDownload && run.Status == "completed" {
		var downloaded WorkspaceUploadResult
		if json.Unmarshal(output.raw.Stdout, &downloaded) == nil {
			result.File = &domain.FileMetadata{Path: downloaded.Path, Size: downloaded.Size, SHA256: downloaded.SHA256}
			result.Stdout = ""
		}
	}
	return result
}
