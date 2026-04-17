package boundaryai

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	// Arrange
	apiKey := "bai_test_key_123"
	baseURL := "https://engine.boundaryai.ai"

	// Act
	client := NewClient(apiKey, baseURL)

	// Assert
	if client.APIKey != apiKey {
		t.Errorf("expected APIKey %q, got %q", apiKey, client.APIKey)
	}
	if client.BaseURL != baseURL {
		t.Errorf("expected BaseURL %q, got %q", baseURL, client.BaseURL)
	}
	if client.AgentID != "go-agent" {
		t.Errorf("expected default AgentID %q, got %q", "go-agent", client.AgentID)
	}
	if client.FailOpen {
		t.Error("expected FailOpen to default to false")
	}
	if client.client == nil {
		t.Error("expected http.Client to be initialized")
	}
}

func TestNewClientCustomFields(t *testing.T) {
	// Arrange & Act
	client := NewClient("bai_key", "http://localhost:8080")
	client.AgentID = "custom-agent"
	client.FailOpen = true

	// Assert
	if client.AgentID != "custom-agent" {
		t.Errorf("expected AgentID %q, got %q", "custom-agent", client.AgentID)
	}
	if !client.FailOpen {
		t.Error("expected FailOpen to be true after setting")
	}
}

func TestAction(t *testing.T) {
	// Arrange & Act
	reversible := true
	action := Action{
		Type:       "system.command",
		Scope:      "rm -rf /tmp/test",
		Count:      1,
		Reversible: &reversible,
		Params:     map[string]string{"cwd": "/home/user"},
	}

	// Assert
	if action.Type != "system.command" {
		t.Errorf("expected Type %q, got %q", "system.command", action.Type)
	}
	if action.Scope != "rm -rf /tmp/test" {
		t.Errorf("expected Scope %q, got %q", "rm -rf /tmp/test", action.Scope)
	}
	if action.Count != 1 {
		t.Errorf("expected Count 1, got %d", action.Count)
	}
	if action.Reversible == nil || !*action.Reversible {
		t.Error("expected Reversible to be true")
	}
	if action.Params["cwd"] != "/home/user" {
		t.Errorf("expected Params[cwd] %q, got %q", "/home/user", action.Params["cwd"])
	}
}

func TestActionJSON(t *testing.T) {
	// Arrange
	action := Action{
		Type:  "api.call",
		Scope: "https://api.example.com/data",
	}

	// Act
	data, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("failed to marshal action: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal action: %v", err)
	}

	// Assert
	if decoded["type"] != "api.call" {
		t.Errorf("expected type %q, got %v", "api.call", decoded["type"])
	}
	if decoded["scope"] != "https://api.example.com/data" {
		t.Errorf("expected scope in JSON, got %v", decoded["scope"])
	}
	// omitempty: count=0 should not be present
	if _, exists := decoded["count"]; exists {
		t.Error("expected count to be omitted when zero")
	}
}

func TestDecisionFields(t *testing.T) {
	// Arrange
	raw := `{
		"decision": "block",
		"reason": "Dangerous command detected",
		"boundary_rule": "rule_system_command_block",
		"evaluation_time_ms": 2.5,
		"audit_id": "aud_123",
		"policy_version": "v3"
	}`

	// Act
	var d Decision
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		t.Fatalf("failed to unmarshal decision: %v", err)
	}
	d.Allowed = d.Decision == "allow"
	d.Blocked = d.Decision == "block"
	d.NeedsConfirm = d.Decision == "confirm"

	// Assert
	if !d.Blocked {
		t.Error("expected Blocked=true for decision=block")
	}
	if d.Allowed {
		t.Error("expected Allowed=false for decision=block")
	}
	if d.NeedsConfirm {
		t.Error("expected NeedsConfirm=false for decision=block")
	}
	if d.Reason != "Dangerous command detected" {
		t.Errorf("unexpected reason: %q", d.Reason)
	}
	if d.BoundaryRule != "rule_system_command_block" {
		t.Errorf("unexpected boundary_rule: %q", d.BoundaryRule)
	}
	if d.EvalTimeMs != 2.5 {
		t.Errorf("expected eval_time_ms 2.5, got %f", d.EvalTimeMs)
	}
	if d.AuditID != "aud_123" {
		t.Errorf("unexpected audit_id: %q", d.AuditID)
	}
}

func TestDecisionAllow(t *testing.T) {
	// Arrange
	raw := `{"decision": "allow", "reason": "Safe operation"}`

	// Act
	var d Decision
	json.Unmarshal([]byte(raw), &d)
	d.Allowed = d.Decision == "allow"
	d.Blocked = d.Decision == "block"
	d.NeedsConfirm = d.Decision == "confirm"

	// Assert
	if !d.Allowed {
		t.Error("expected Allowed=true")
	}
	if d.Blocked {
		t.Error("expected Blocked=false")
	}
}

func TestDecisionConfirm(t *testing.T) {
	// Arrange
	raw := `{"decision": "confirm", "reason": "Human review required"}`

	// Act
	var d Decision
	json.Unmarshal([]byte(raw), &d)
	d.Allowed = d.Decision == "allow"
	d.Blocked = d.Decision == "block"
	d.NeedsConfirm = d.Decision == "confirm"

	// Assert
	if !d.NeedsConfirm {
		t.Error("expected NeedsConfirm=true")
	}
	if d.Allowed || d.Blocked {
		t.Error("expected Allowed=false and Blocked=false for confirm")
	}
}

func TestEvaluateSuccess(t *testing.T) {
	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/evaluate" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("X-Boundary-Key") != "bai_test" {
			t.Errorf("missing or wrong API key header")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("missing Content-Type header")
		}

		var req evalRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if req.Action.Type != "system.command" {
			t.Errorf("expected action type system.command, got %s", req.Action.Type)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"decision":           "block",
			"reason":             "Destructive command blocked",
			"boundary_rule":      "rule_destructive_cmd",
			"evaluation_time_ms": 1.23,
			"audit_id":           "aud_test_456",
		})
	}))
	defer server.Close()

	client := NewClient("bai_test", server.URL)

	// Act
	decision, err := client.Evaluate(Action{
		Type:  "system.command",
		Scope: "rm -rf /",
	})

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Blocked {
		t.Error("expected decision to be blocked")
	}
	if decision.Allowed {
		t.Error("expected decision to not be allowed")
	}
	if decision.Reason != "Destructive command blocked" {
		t.Errorf("unexpected reason: %q", decision.Reason)
	}
	if decision.BoundaryRule != "rule_destructive_cmd" {
		t.Errorf("unexpected boundary_rule: %q", decision.BoundaryRule)
	}
}

func TestEvaluateAllow(t *testing.T) {
	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"decision":           "allow",
			"reason":             "Safe command",
			"evaluation_time_ms": 0.5,
		})
	}))
	defer server.Close()

	client := NewClient("bai_test", server.URL)

	// Act
	decision, err := client.Evaluate(Action{
		Type:  "system.command",
		Scope: "ls -la",
	})

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Allowed {
		t.Error("expected decision to be allowed")
	}
	if decision.Blocked {
		t.Error("expected decision to not be blocked")
	}
}

func TestEvaluateFailClosed(t *testing.T) {
	// Arrange — no server, unreachable URL
	client := NewClient("bai_test", "http://127.0.0.1:1")
	client.FailOpen = false

	// Act
	decision, err := client.Evaluate(Action{Type: "test"})

	// Assert
	if err == nil {
		t.Error("expected error for unreachable server")
	}
	if decision == nil {
		t.Fatal("expected non-nil decision even on error")
	}
	if !decision.Blocked {
		t.Error("expected fail-closed to block")
	}
	if decision.Allowed {
		t.Error("expected fail-closed to not allow")
	}
}

func TestEvaluateFailOpen(t *testing.T) {
	// Arrange — no server, unreachable URL
	client := NewClient("bai_test", "http://127.0.0.1:1")
	client.FailOpen = true

	// Act
	decision, err := client.Evaluate(Action{Type: "test"})

	// Assert
	if err == nil {
		t.Error("expected error for unreachable server")
	}
	if decision == nil {
		t.Fatal("expected non-nil decision even on error")
	}
	if !decision.Allowed {
		t.Error("expected fail-open to allow")
	}
	if decision.Blocked {
		t.Error("expected fail-open to not block")
	}
}

func TestEvaluateRetryOn500(t *testing.T) {
	// Arrange
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"decision":           "allow",
			"reason":             "Recovered after retries",
			"evaluation_time_ms": 1.0,
		})
	}))
	defer server.Close()

	client := NewClient("bai_test", server.URL)

	// Act
	decision, err := client.Evaluate(Action{Type: "test"})

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Allowed {
		t.Error("expected allow after successful retry")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestHealth(t *testing.T) {
	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"healthy"}`))
	}))
	defer server.Close()

	client := NewClient("bai_test", server.URL)

	// Act
	healthy, err := client.Health()

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !healthy {
		t.Error("expected healthy=true")
	}
}

func TestHealthUnhealthy(t *testing.T) {
	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer server.Close()

	client := NewClient("bai_test", server.URL)

	// Act
	healthy, err := client.Health()

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if healthy {
		t.Error("expected healthy=false for 503")
	}
}

func TestScanPII(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "SSN detected",
			input:    "My SSN is 123-45-6789",
			expected: []string{"SSN"},
		},
		{
			name:     "credit card detected",
			input:    "Card: 4111 1111 1111 1111",
			expected: []string{"credit_card"},
		},
		{
			name:     "AWS key detected",
			input:    "Key: AKIAIOSFODNN7EXAMPLE",
			expected: []string{"aws_key"},
		},
		{
			name:     "API key detected",
			input:    "Token: sk-abcdefghijklmnopqrstuvwxyz",
			expected: []string{"api_key"},
		},
		{
			name:     "password detected",
			input:    "password: supersecret123",
			expected: []string{"password"},
		},
		{
			name:     "GitHub PAT detected",
			input:    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			expected: []string{"github_pat"},
		},
		{
			name:     "clean text",
			input:    "Hello, this is a normal message with no sensitive data.",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			found := ScanPII(tt.input)

			// Assert
			if tt.expected == nil {
				if len(found) != 0 {
					t.Errorf("expected no PII, found %v", found)
				}
				return
			}

			for _, exp := range tt.expected {
				contains := false
				for _, f := range found {
					if f == exp {
						contains = true
						break
					}
				}
				if !contains {
					t.Errorf("expected to find %q in PII results %v", exp, found)
				}
			}
		})
	}
}

func TestEvaluateBatch(t *testing.T) {
	// Arrange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/evaluate/batch" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"decisions": []map[string]interface{}{
				{
					"decision":           "allow",
					"reason":             "safe",
					"evaluation_time_ms": 0.5,
				},
				{
					"decision":           "block",
					"reason":             "dangerous",
					"boundary_rule":      "rule_block",
					"evaluation_time_ms": 0.8,
				},
			},
		})
	}))
	defer server.Close()

	client := NewClient("bai_test", server.URL)

	// Act
	decisions, err := client.EvaluateBatch([]Action{
		{Type: "system.command", Scope: "ls"},
		{Type: "system.command", Scope: "rm -rf /"},
	})

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(decisions) != 2 {
		t.Fatalf("expected 2 decisions, got %d", len(decisions))
	}
	if !decisions[0].Allowed {
		t.Error("expected first decision to be allowed")
	}
	if !decisions[1].Blocked {
		t.Error("expected second decision to be blocked")
	}
}

func TestVersion(t *testing.T) {
	if Version == "" {
		t.Error("expected Version to be non-empty")
	}
	if Version != "0.6.0" {
		t.Errorf("expected Version 0.6.0, got %s", Version)
	}
}
