package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/laiwf94/authz/internal/authn/config"
	"github.com/laiwf94/authz/internal/authn/oidc"
	"github.com/laiwf94/authz/internal/authn/session"
	"github.com/laiwf94/authz/internal/platform/audit"
)

// Revalidation: each session at an OpenID provider with revalidate set is
// confirmed every interval by redeeming its refresh token. The token is
// sealed at rest, bound to the provider and subject it was issued for.
const (
	purposeRefresh = "refresh"
	// RevalidateEvery is how often RunRevalidation looks for sessions that
	// are due; a session is confirmed at most this long after its time.
	RevalidateEvery = 10 * time.Second
	// revalidateWorkers bounds concurrent refresh requests across all
	// providers, so a pass never floods a provider.
	revalidateWorkers = 8
	// revalidateBatch bounds the sessions one pass takes per provider; the
	// rest, oldest first, go in the next pass.
	revalidateBatch = 2000
	// revalidateTimeout bounds one pass.
	revalidateTimeout = 2 * time.Minute
	bindingBytes      = 16
)

// Reasons a revalidation ends a session, as audited.
const (
	reasonRefreshRefused    = oidc.ReasonRefreshRefused
	reasonRefreshFailed     = oidc.ReasonRefreshFailed
	reasonNoRefreshToken    = "no_refresh_token"
	reasonRefreshUnreadable = "refresh_token_unreadable"
)

// revalidation is a provider's revalidate setting; the zero value is off.
type revalidation struct {
	interval time.Duration
	grace    time.Duration // 0: end at the first failure
}

func revalidationOf(r config.Revalidate) revalidation {
	if !r.Enabled() {
		return revalidation{}
	}
	rv := revalidation{interval: time.Duration(r.Interval)}
	if r.OnFailure == config.RevalidateGrace {
		rv.grace = time.Duration(r.Grace)
	}
	return rv
}

func (r revalidation) enabled() bool { return r.interval > 0 }

// binding ties a sealed refresh token to the provider and subject it was
// issued for, so a token moved to another session's record doesn't open.
func binding(provider, subject string) []byte {
	sum := sha256.Sum256([]byte(provider + "\x00" + subject))
	return sum[:bindingBytes]
}

func (s *Server) sealRefresh(provider, subject, token string) string {
	return s.keys.Seal(purposeRefresh, append(binding(provider, subject), token...))
}

func (s *Server) openRefresh(provider, subject, sealed string) (string, error) {
	b, err := s.keys.Open(purposeRefresh, sealed)
	if err != nil {
		return "", err
	}
	if len(b) <= bindingBytes || subtle.ConstantTimeCompare(b[:bindingBytes], binding(provider, subject)) != 1 {
		return "", errors.New("refresh token sealed for another session")
	}
	return string(b[bindingBytes:]), nil
}

// RevalidateResult counts what one pass did.
type RevalidateResult struct {
	Checked   int // sessions that were due
	Confirmed int // the provider vouched for them
	Ended     int // refused, or failed past the grace
	Kept      int // failed, inside the grace
}

// RunRevalidation calls Revalidate every period until ctx ends.
func (s *Server) RunRevalidation(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Revalidate(ctx)
		}
	}
}

type revalidateJob struct {
	p   *provider
	due session.Due
}

// Revalidate asks the identity providers about every session that is due.
// A session the provider refuses ends; one it can't be asked about ends at
// once or, with on_failure "grace", once its grace has passed. Passes don't
// overlap: a call while one runs returns at once with nothing done.
func (s *Server) Revalidate(ctx context.Context) RevalidateResult {
	if !s.revalMu.TryLock() {
		return RevalidateResult{}
	}
	defer s.revalMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, revalidateTimeout)
	defer cancel()
	rt := s.rt.Load()
	now := s.now()
	var jobs []revalidateJob
	for _, p := range rt.providers {
		if p.oidc == nil || !p.reval.enabled() {
			continue
		}
		for _, d := range s.sessions.Due(p.id, now.Add(-p.reval.interval), revalidateBatch) {
			jobs = append(jobs, revalidateJob{p: p, due: d})
		}
	}
	var (
		mu  sync.Mutex
		res = RevalidateResult{Checked: len(jobs)}
		wg  sync.WaitGroup
		ch  = make(chan revalidateJob)
	)
	for range min(revalidateWorkers, len(jobs)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				out := s.revalidateOne(ctx, j.p, j.due)
				mu.Lock()
				switch out {
				case outcomeConfirmed:
					res.Confirmed++
				case outcomeEnded:
					res.Ended++
				case outcomeKept:
					res.Kept++
				}
				mu.Unlock()
			}
		}()
	}
	for _, j := range jobs {
		if ctx.Err() != nil {
			break
		}
		ch <- j
	}
	close(ch)
	wg.Wait()
	return res
}

type outcome int

const (
	outcomeNone outcome = iota // nothing to do: the session ended meanwhile, or the pass was cancelled
	outcomeConfirmed
	outcomeEnded
	outcomeKept
)

func (s *Server) revalidateOne(ctx context.Context, p *provider, d session.Due) outcome {
	if ctx.Err() != nil {
		return outcomeNone
	}
	started := s.now()
	reason := ""
	var cause error
	token, err := "", error(nil)
	switch {
	case d.Refresh == "":
		reason, cause = reasonNoRefreshToken, errors.New("the provider issued no refresh token at login")
	default:
		if token, err = s.openRefresh(p.id, d.Subject, d.Refresh); err != nil {
			reason, cause = reasonRefreshUnreadable, err
		}
	}
	if reason == "" {
		res, err := p.oidc.Refresh(ctx, token, d.Subject)
		if err == nil {
			sealed := ""
			if res.Rotated {
				sealed = s.sealRefresh(p.id, d.Subject, res.RefreshToken)
			}
			if err := s.sessions.Revalidated(d.ID, sealed, started); err != nil && !errors.Is(err, session.ErrNotFound) {
				s.log.Error("saving a session revalidation", "provider", p.id, "session", d.ID, "error", err.Error())
			}
			s.revalidated(p.id, "confirmed")
			return outcomeConfirmed
		}
		if ctx.Err() != nil {
			// The pass ran out of time or is shutting down: no answer, and
			// not the provider's fault.
			return outcomeNone
		}
		reason, cause = reasonOf(err), err
		if reason == reasonRefreshRefused {
			s.endSession(p, d, reason, cause)
			s.revalidated(p.id, "refused")
			return outcomeEnded
		}
		if reason != reasonRefreshFailed {
			reason = reasonRefreshFailed
		}
	}
	// No answer about the user: the failure policy decides.
	if p.reval.grace > 0 && started.Before(d.Revalidated.Add(p.reval.interval+p.reval.grace)) {
		s.log.Warn("session revalidation failed; keeping the session inside its grace", "provider", p.id,
			"session", d.ID, "reason", reason, "error", cause.Error(),
			"ends_at", d.Revalidated.Add(p.reval.interval+p.reval.grace).UTC().Format(time.RFC3339))
		s.revalidated(p.id, "kept")
		return outcomeKept
	}
	s.endSession(p, d, reason, cause)
	s.revalidated(p.id, "failed")
	return outcomeEnded
}

func (s *Server) revalidated(provider, result string) {
	s.m.Counter("wicket_revalidations_total", `provider="`+provider+`",result="`+result+`"`,
		"Session revalidations by provider and result: confirmed, refused, failed (ended) or kept (inside the grace).").Inc()
}

// endSession ends a session the provider no longer vouches for.
func (s *Server) endSession(p *provider, d session.Due, reason string, cause error) {
	ok, err := s.sessions.Revoke(d.ID)
	if err != nil {
		s.log.Error("ending a session after revalidation", "provider", p.id, "session", d.ID, "error", err.Error())
	}
	if !ok {
		return // it ended meanwhile
	}
	ctx := context.Background()
	s.audit(ctx, audit.Envelope{Actor: d.Subject, Subject: "session:" + d.ID, Action: "session.end"},
		audit.SessionEnded{Provider: p.id, Session: d.ID, Reason: reason},
		slog.String("provider", p.id), slog.String("sub", d.Subject), slog.String("session", d.ID),
		slog.String("reason", reason), slog.String("error", cause.Error()))
	s.m.Counter("wicket_sessions_ended_total", `reason="`+reason+`"`, "Sessions ended because the identity provider no longer vouched for them.").Inc()
}
