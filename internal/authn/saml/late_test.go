package saml

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// lateTransport answers only once the request's context has ended, with an
// empty 200: what the transport can hand back when the server answers
// because it saw the client give up (#234).
type lateTransport struct{}

func (lateTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	<-r.Context().Done()
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}, Request: r}, nil
}

func TestFetchMetadataLateAnswerIsADeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := FetchIdPMetadata(ctx, &http.Client{Transport: lateTransport{}}, "https://idp.example.com/metadata")
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("late empty 200: %v, want the deadline", err)
	}
}
