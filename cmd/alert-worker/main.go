// SecOps alert worker: read GATE_RESULT.json and notify Slack/Discord on failure.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type gateResult struct {
	Passed      bool     `json:"passed"`
	Reasons     []string `json:"reasons"`
	SummaryPath string   `json:"summary_path"`
	Repository  string   `json:"repository"`
	Ref         string   `json:"ref"`
}

func main() {
	webhook := strings.TrimSpace(os.Getenv("SECOPS_ALERT_WEBHOOK"))
	if webhook == "" {
		fmt.Println("SECOPS_ALERT_WEBHOOK not set; skip alert")
		return
	}

	path := strings.TrimSpace(os.Getenv("SECOPS_GATE_RESULT_PATH"))
	if path == "" {
		path = "reports/GATE_RESULT.json"
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read gate result: %v\n", err)
		os.Exit(1)
	}

	var result gateResult
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Fprintf(os.Stderr, "parse gate result: %v\n", err)
		os.Exit(1)
	}

	if result.Passed {
		fmt.Println("Gate PASSED; no SecOps alert sent")
		return
	}

	message := buildMessage(result)
	if err := postWebhook(webhook, message); err != nil {
		fmt.Fprintf(os.Stderr, "webhook post failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("SecOps alert sent")
}

func buildMessage(result gateResult) string {
	var b strings.Builder
	b.WriteString("*SecOps Gate FAILED*\n")
	if result.Repository != "" {
		b.WriteString(fmt.Sprintf("Repo: `%s`\n", result.Repository))
	}
	if result.Ref != "" {
		b.WriteString(fmt.Sprintf("Ref: `%s`\n", result.Ref))
	}
	if result.SummaryPath != "" {
		b.WriteString(fmt.Sprintf("Summary: `%s`\n", result.SummaryPath))
	}
	b.WriteString("\n*Reasons:*\n")
	for _, reason := range result.Reasons {
		b.WriteString(fmt.Sprintf("- %s\n", reason))
	}
	if len(result.Reasons) == 0 {
		b.WriteString("- (no reasons recorded)\n")
	}
	return b.String()
}

func postWebhook(webhookURL, message string) error {
	format := strings.ToLower(strings.TrimSpace(os.Getenv("SECOPS_ALERT_FORMAT")))
	if format == "" {
		format = "slack"
	}

	var payload any
	switch format {
	case "discord":
		payload = map[string]string{"content": message}
	default:
		payload = map[string]string{"text": message}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		slurp, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(slurp))
	}
	return nil
}
