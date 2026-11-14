package oidc

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// lateTransport answers only once the request's context has ended, with a
// 200 and a JSON body (#234).
type lateTransport struct{}

func (lateTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	<-r.Context().Done()
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}, Request: r}, nil
}

func TestLateAnswerIsADeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, _, err := get(ctx, &http.Client{Transport: lateTransport{}}, "https://op.example.com/.well-known/openid-configuration", "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late 200: %v, want the deadline", err)
	}
}
