// Package boundaryai provides a Go client for the BoundaryAI universal AI firewall.
//
// Usage:
//
//	client := boundaryai.NewClient("bai_xxx", "https://engine.boundaryai.ai")
//	decision, err := client.Evaluate(boundaryai.Action{
//	    Type:  "system.command",
//	    Scope: "rm -rf /data",
//	})
//	if decision.Blocked {
//	    log.Fatal("Action blocked:", decision.Reason)
//	}
package boundaryai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const Version = "0.6.0"
const maxRetries = 3
const baseDelay = 100 * time.Millisecond

// Client communicates with the BoundaryAI enforcement engine.
type Client struct {
	APIKey   string
	BaseURL  string
	AgentID  string
	Timeout  time.Duration
	FailOpen bool
	client   *http.Client
}

// NewClient creates a new BoundaryAI client.
func NewClient(apiKey, baseURL string) *Client {
	return &Client{
		APIKey:   apiKey,
		BaseURL:  baseURL,
		AgentID:  "go-agent",
		Timeout:  5 * time.Second,
		FailOpen: false,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Action describes what the agent wants to do.
type Action struct {
	Type       string            `json:"type"`
	Scope      string            `json:"scope,omitempty"`
	Count      int               `json:"count,omitempty"`
	Reversible *bool             `json:"reversible,omitempty"`
	Params     map[string]string `json:"params,omitempty"`
}

// Decision is the enforcement verdict.
type Decision struct {
	Decision      string  `json:"decision"`
	Reason        string  `json:"reason"`
	BoundaryRule  string  `json:"boundary_rule"`
	EvalTimeMs    float64 `json:"evaluation_time_ms"`
	AuditID       string  `json:"audit_id"`
	PolicyVersion string  `json:"policy_version"`
	Allowed       bool
	Blocked       bool
	NeedsConfirm  bool
}

type evalRequest struct {
	AgentID string      `json:"agent_id"`
	Action  Action      `json:"action"`
	Context evalContext `json:"context"`
}

type evalContext struct {
	Environment string `json:"environment,omitempty"`
	Timestamp   string `json:"timestamp"`
	UserID      string `json:"user_id,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
}

// Evaluate checks an action against boundary policies.
// Retries up to 3 times with exponential backoff on transient failures.
func (c *Client) Evaluate(action Action) (*Decision, error) {
	hostname, _ := os.Hostname()
	payload := evalRequest{
		AgentID: c.AgentID,
		Action:  action,
		Context: evalContext{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			UserID:    os.Getenv("USER"),
			Hostname:  hostname,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return c.failDecision(err), err
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(baseDelay * time.Duration(1<<uint(attempt-1)))
		}

		req, err := http.NewRequest("POST", c.BaseURL+"/v1/evaluate", bytes.NewReader(body))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Boundary-Key", c.APIKey)

		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		// Retry on 429 or 5xx
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}

		var d Decision
		if err := json.Unmarshal(respBody, &d); err != nil {
			lastErr = err
			continue
		}

		d.Allowed = d.Decision == "allow"
		d.Blocked = d.Decision == "block"
		d.NeedsConfirm = d.Decision == "confirm"

		return &d, nil
	}

	return c.failDecision(lastErr), lastErr
}

// EvaluateBatch evaluates multiple actions in a single request.
func (c *Client) EvaluateBatch(actions []Action) ([]*Decision, error) {
	type batchReq struct {
		AgentID string   `json:"agent_id"`
		Actions []Action `json:"actions"`
	}
	body, err := json.Marshal(batchReq{AgentID: c.AgentID, Actions: actions})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/v1/evaluate/batch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Boundary-Key", c.APIKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var results struct {
		Decisions []Decision `json:"decisions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}

	out := make([]*Decision, len(results.Decisions))
	for i := range results.Decisions {
		d := &results.Decisions[i]
		d.Allowed = d.Decision == "allow"
		d.Blocked = d.Decision == "block"
		d.NeedsConfirm = d.Decision == "confirm"
		out[i] = d
	}
	return out, nil
}

// Health checks if the engine is reachable.
func (c *Client) Health() (bool, error) {
	resp, err := c.client.Get(c.BaseURL + "/health")
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, nil
}

// ScanPII checks text for common PII patterns (SSN, credit cards, API keys, etc.).
func ScanPII(text string) []string {
	patterns := map[string]*regexp.Regexp{
		"SSN":         regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		"credit_card": regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`),
		"aws_key":     regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		"api_key":     regexp.MustCompile(`\b(sk-|pk_|rk_)[A-Za-z0-9]{20,}\b`),
		"password":    regexp.MustCompile(`(?i)\bpassword\s*[:=]\s*\S+`),
		"github_pat":  regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`),
	}
	var found []string
	lower := strings.ToLower(text)
	for name, pat := range patterns {
		if pat.MatchString(lower) || pat.MatchString(text) {
			found = append(found, name)
		}
	}
	return found
}

func (c *Client) failDecision(err error) *Decision {
	decision := "block"
	reason := fmt.Sprintf("Engine unreachable (fail-closed): %v", err)
	if c.FailOpen {
		decision = "allow"
		reason = fmt.Sprintf("Engine unreachable (fail-open): %v", err)
	}
	return &Decision{
		Decision: decision,
		Reason:   reason,
		Allowed:  c.FailOpen,
		Blocked:  !c.FailOpen,
	}
}
