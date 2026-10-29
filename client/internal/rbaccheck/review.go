package rbaccheck

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"meshtransit.net/client/internal/kubetoken"
)

const (
	// reviewTimeout bounds one SelfSubjectAccessReview.
	reviewTimeout = 10 * time.Second
	// maxReviewAnswer bounds what is read of an answer.
	maxReviewAnswer = 64 << 10
	// Device and owner names the minter keys the checker's tokens under, so
	// its tokens show apart in the gateway's log (K1b design §9).
	checkDevice, checkOwner = "rbaccheck", "gateway"
)

// APIReviewer asks the API server over plain REST, as kubetoken does: the
// cluster's CA, no proxy, no redirect.
type APIReviewer struct {
	client *http.Client
	url    string
}

// NewAPIReviewer makes a reviewer for the API server at server.
func NewAPIReviewer(server, caFile string) (*APIReviewer, error) {
	parsed, err := url.Parse(server)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || strings.Trim(parsed.Path, "/") != "" {
		return nil, errors.New("rbaccheck: the API server must be an https URL")
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("rbaccheck: reading the cluster CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("rbaccheck: the cluster CA file holds no certificate")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true, IdleConnTimeout: 90 * time.Second}
	return &APIReviewer{
		client: &http.Client{Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		url: strings.TrimSuffix(server, "/") + "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
	}, nil
}

type accessReview struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		ResourceAttributes resourceAttributes `json:"resourceAttributes"`
	} `json:"spec"`
}

type resourceAttributes struct {
	Namespace   string `json:"namespace,omitempty"`
	Verb        string `json:"verb"`
	Group       string `json:"group"`
	Resource    string `json:"resource"`
	Subresource string `json:"subresource,omitempty"`
	Name        string `json:"name,omitempty"`
}

// Review implements Reviewer. Allowed is the API server's answer; a token
// it refuses is ErrUnauthorized.
func (reviewer *APIReviewer) Review(ctx context.Context, token string, attributes Attributes) (bool, error) {
	review := accessReview{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}
	review.Spec.ResourceAttributes = resourceAttributes{Namespace: attributes.Namespace, Verb: attributes.Verb,
		Group: attributes.Group, Resource: attributes.Resource, Subresource: attributes.Subresource,
		Name: attributes.Name}
	body, err := json.Marshal(review)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, reviewTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, reviewer.url, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := reviewer.client.Do(request)
	if err != nil {
		return false, fmt.Errorf("rbaccheck: reviewing: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxReviewAnswer))
	if err != nil {
		return false, fmt.Errorf("rbaccheck: reading the review: %w", err)
	}
	switch response.StatusCode {
	case http.StatusCreated, http.StatusOK:
	case http.StatusUnauthorized:
		return false, ErrUnauthorized
	default:
		return false, fmt.Errorf("rbaccheck: the API server answered %d", response.StatusCode)
	}
	var answer struct {
		Status *struct {
			Allowed         bool   `json:"allowed"`
			EvaluationError string `json:"evaluationError"`
		} `json:"status"`
	}
	if err := json.Unmarshal(payload, &answer); err != nil || answer.Status == nil {
		return false, errors.New("rbaccheck: a review without a status")
	}
	// An authorizer that failed to answer (a webhook timing out) leaves a
	// denial that may not be one: an error, never "not held" (review b4 M2).
	if !answer.Status.Allowed && answer.Status.EvaluationError != "" {
		// Its text names the binding at fault (a dangling one turns every
		// group off); it reaches Verdict.Detail, not users.
		return false, fmt.Errorf("rbaccheck: an authorizer could not evaluate the review: %.256s",
			answer.Status.EvaluationError)
	}
	return answer.Status.Allowed, nil
}

// MinterTokens hands out the checker's tokens from the gateway's minter.
type MinterTokens struct {
	Minter *kubetoken.Minter

	mu   sync.Mutex
	held map[string]kubetoken.Token // by group: the last handed out
}

// Token implements Tokens.
func (tokens *MinterTokens) Token(ctx context.Context, group string) (string, error) {
	token, err := tokens.Minter.For(ctx, checkDevice, checkOwner, group)
	if err != nil {
		return "", err
	}
	tokens.mu.Lock()
	defer tokens.mu.Unlock()
	if tokens.held == nil {
		tokens.held = map[string]kubetoken.Token{}
	}
	tokens.held[group] = token
	return token.Value(), nil
}

// Forget implements Tokens.
func (tokens *MinterTokens) Forget(group, value string) {
	tokens.mu.Lock()
	token, found := tokens.held[group]
	tokens.mu.Unlock()
	if found && token.Value() == value {
		tokens.Minter.Forget(checkDevice, checkOwner, group, token)
	}
}
