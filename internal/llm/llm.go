// Package llm asks a GitHub Models chat model whether a CVE that is genuinely
// linked into a binary is plausibly exploitable in that context. It is an
// optional, advisory layer on top of the deterministic pclntab / govulncheck
// analysis.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// DefaultEndpoint is the GitHub Models OpenAI-compatible inference endpoint.
const DefaultEndpoint = "https://models.github.ai/inference/chat/completions"

// DefaultModel is used when no model is specified.
const DefaultModel = "openai/gpt-4o"

// Verdict is the model's structured assessment.
type Verdict struct {
	Exploitable string `json:"exploitable"` // "likely" | "unlikely" | "unknown"
	Confidence  string `json:"confidence"`  // "low" | "medium" | "high"
	Rationale   string `json:"rationale"`
}

// Request describes one CVE to assess in the context of a specific binary.
type Request struct {
	CVE       string
	Module    string
	Version   string
	Packages  []string
	Binary    string
	Reachable string // "linked" | "reachable" | "unknown"
}

// Client talks to the GitHub Models API.
type Client struct {
	HTTP     *http.Client
	Endpoint string
	Model    string
	Token    string
}

// NewClient builds a Client. The token is read from GITHUB_TOKEN (or GH_TOKEN)
// unless supplied explicitly. It returns an error if no token is available.
func NewClient(model, token string) (*Client, error) {
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("no GitHub token found (set GITHUB_TOKEN or GH_TOKEN)")
	}
	if model == "" {
		model = DefaultModel
	}
	return &Client{
		HTTP:     &http.Client{Timeout: 60 * time.Second},
		Endpoint: DefaultEndpoint,
		Model:    model,
		Token:    token,
	}, nil
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

const systemPrompt = `You are a security analyst assessing Go dependency vulnerabilities (VEX triage).
You are given a CVE whose vulnerable package has been confirmed to be linked into (and possibly reachable from) a shipped Go binary.
Judge how plausibly the vulnerability is actually EXPLOITABLE in a typical deployment of this binary.
Consider: whether the vulnerable functions are likely invoked with attacker-controlled input, network exposure, and typical usage of the package.
Respond with ONLY a JSON object, no prose, of the form:
{"exploitable":"likely|unlikely|unknown","confidence":"low|medium|high","rationale":"one or two sentences"}`

// Assess returns the model's verdict for a single CVE.
func (c *Client) Assess(ctx context.Context, r Request) (*Verdict, error) {
	reach := r.Reachable
	if reach == "" {
		reach = "unknown"
	}
	user := fmt.Sprintf(
		"CVE: %s\nModule: %s@%s\nVulnerable packages: %s\nBinary: %s\nStatic analysis says the vulnerable code is: %s\nAssess exploitability.",
		r.CVE, r.Module, r.Version, strings.Join(r.Packages, ", "), r.Binary, reach,
	)

	reqBody := chatRequest{
		Model:       c.Model,
		Temperature: 0,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: user},
		},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.Token)
	httpReq.Header.Set("Accept", "application/json")

	res, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	var cr chatResponse
	if err := json.NewDecoder(res.Body).Decode(&cr); err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		if cr.Error != nil {
			return nil, fmt.Errorf("github models: %s (status %d)", cr.Error.Message, res.StatusCode)
		}
		return nil, fmt.Errorf("github models: unexpected status %d", res.StatusCode)
	}
	if len(cr.Choices) == 0 {
		return nil, fmt.Errorf("github models: empty response")
	}
	return parseVerdict(cr.Choices[0].Message.Content)
}

var jsonObjRe = regexp.MustCompile(`(?s)\{.*\}`)

// parseVerdict extracts the JSON object from a model reply, tolerating stray
// markdown fences or prose around it.
func parseVerdict(content string) (*Verdict, error) {
	match := jsonObjRe.FindString(content)
	if match == "" {
		return &Verdict{Exploitable: "unknown", Confidence: "low", Rationale: strings.TrimSpace(content)}, nil
	}
	var v Verdict
	if err := json.Unmarshal([]byte(match), &v); err != nil {
		return &Verdict{Exploitable: "unknown", Confidence: "low", Rationale: strings.TrimSpace(content)}, nil
	}
	if v.Exploitable == "" {
		v.Exploitable = "unknown"
	}
	return &v, nil
}
