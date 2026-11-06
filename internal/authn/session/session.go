// Package session keeps server-side sessions: in memory, optionally backed by
// an append-only log so sessions and revocations survive restarts.
//
// The browser holds only a random 256-bit secret (inside a sealed cookie).
// The store keys sessions by a hash of that secret, so neither the log file
// nor the admin API ever contains a value that could be replayed as a cookie.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/laiwf94/authz/internal/authn/policy"
)

// Defaults and limits.
const (
	DefaultIdleTimeout     = 8 * time.Hour
	DefaultAbsoluteTimeout = 24 * time.Hour
	DefaultMaxSessions     = 100_000
	DefaultMaxPerSubject   = 20
	// touchInterval bounds how often a session's last-seen time is written
	// to the log. Idle expiry is therefore accurate to this interval after a
	// restart, and only ever in the safe direction (earlier).
	touchInterval = time.Minute
	secretBytes   = 32
)

// compactSlack is how many dead records the log may hold beyond twice the
// live sessions before Sweep rewrites it.
var compactSlack = 1024

// Errors.
var (
	ErrNotFound    = errors.New("session: not found or expired")
	ErrFull        = errors.New("session: too many sessions")
	ErrUnavailable = errors.New("session: storage unavailable")
	ErrExpired     = errors.New("session: the identity provider's session has already ended")
)

// Session is one signed-in browser.
type Session struct {
	ID        string          `json:"id"` // public handle, safe to show and log
	Identity  policy.Identity `json:"identity"`
	CreatedAt time.Time       `json:"created_at"`
	LastSeen  time.Time       `json:"last_seen_at"`
	ExpiresAt time.Time       `json:"expires_at"` // absolute expiry

	persistedSeen time.Time
}

// Options configures a Store.
type Options struct {
	// Path of the append-only log; empty keeps sessions in memory only.
	Path            string
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	MaxSessions     int
	MaxPerSubject   int
	Now             func() time.Time
}

// Store holds sessions. It is safe for concurrent use.
type Store struct {
	opts Options

	mu        sync.Mutex
	byID      map[string]*Session
	bySubject map[string]map[string]bool
	log       *logFile // nil when in memory only
}

// Open loads the log at opts.Path (if any), drops expired sessions and
// compacts the log.
func Open(opts Options) (*Store, error) {
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = DefaultIdleTimeout
	}
	if opts.AbsoluteTimeout <= 0 {
		opts.AbsoluteTimeout = DefaultAbsoluteTimeout
	}
	if opts.MaxSessions <= 0 {
		opts.MaxSessions = DefaultMaxSessions
	}
	if opts.MaxPerSubject <= 0 {
		opts.MaxPerSubject = DefaultMaxPerSubject
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	s := &Store{opts: opts, byID: map[string]*Session{}, bySubject: map[string]map[string]bool{}}
	if opts.Path == "" {
		return s, nil
	}
	lf, sessions, err := openLog(opts.Path)
	if err != nil {
		return nil, err
	}
	s.log = lf
	now := opts.Now()
	for _, sess := range sessions {
		if s.live(sess, now) {
			s.index(sess)
		}
	}
	if err := s.log.compact(s.snapshot()); err != nil {
		s.log.close()
		return nil, err
	}
	return s, nil
}

// SetTimeouts changes the idle and absolute timeouts (after a configuration
// reload). The idle timeout applies to existing sessions at once; the
// absolute timeout applies to sessions created from now on.
func (s *Store) SetTimeouts(idle, absolute time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if idle > 0 {
		s.opts.IdleTimeout = idle
	}
	if absolute > 0 {
		s.opts.AbsoluteTimeout = absolute
	}
}

// Close releases the log file.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.log == nil {
		return nil
	}
	return s.log.close()
}

func subjectKey(provider, subject string) string { return provider + "\x00" + subject }

// IDFromSecret derives the public session id from the cookie secret.
func IDFromSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:16])
}

func (s *Store) live(sess *Session, now time.Time) bool {
	return now.Before(sess.ExpiresAt) && now.Sub(sess.LastSeen) < s.opts.IdleTimeout
}

func (s *Store) index(sess *Session) {
	s.byID[sess.ID] = sess
	k := subjectKey(sess.Identity.Provider, sess.Identity.Subject)
	if s.bySubject[k] == nil {
		s.bySubject[k] = map[string]bool{}
	}
	s.bySubject[k][sess.ID] = true
}

func (s *Store) unindex(sess *Session) {
	delete(s.byID, sess.ID)
	k := subjectKey(sess.Identity.Provider, sess.Identity.Subject)
	delete(s.bySubject[k], sess.ID)
	if len(s.bySubject[k]) == 0 {
		delete(s.bySubject, k)
	}
}

func (s *Store) snapshot() []*Session {
	out := make([]*Session, 0, len(s.byID))
	for _, sess := range s.byID {
		out = append(out, sess)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Create starts a session for id and returns the cookie secret. The
// absolute expiry is the configured timeout, or notAfter if that is earlier
// (an identity provider may cap the session, e.g. SAML SessionNotOnOrAfter).
func (s *Store) Create(id policy.Identity, notAfter time.Time) (string, *Session, error) {
	var raw [secretBytes]byte
	_, _ = rand.Read(raw[:])
	secret := base64.RawURLEncoding.EncodeToString(raw[:])
	now := s.opts.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	exp := now.Add(s.opts.AbsoluteTimeout)
	if !notAfter.IsZero() && notAfter.Before(exp) {
		exp = notAfter
	}
	if !exp.After(now) {
		return "", nil, ErrExpired
	}
	sess := &Session{ID: IDFromSecret(secret), Identity: id, CreatedAt: now, LastSeen: now, ExpiresAt: exp, persistedSeen: now}

	if len(s.byID) >= s.opts.MaxSessions {
		s.sweepLocked(now)
		if len(s.byID) >= s.opts.MaxSessions {
			return "", nil, ErrFull
		}
	}
	// Keep at most MaxPerSubject sessions per user: the oldest are revoked.
	var evict []*Session
	if ids := s.bySubject[subjectKey(id.Provider, id.Subject)]; len(ids) >= s.opts.MaxPerSubject {
		for sid := range ids {
			evict = append(evict, s.byID[sid])
		}
		sort.Slice(evict, func(i, j int) bool { return evict[i].CreatedAt.Before(evict[j].CreatedAt) })
		evict = evict[:len(evict)-s.opts.MaxPerSubject+1]
	}
	recs := []record{{Op: opCreate, Session: sess}}
	for _, e := range evict {
		recs = append(recs, record{Op: opRevoke, ID: e.ID})
	}
	if err := s.append(true, recs...); err != nil {
		return "", nil, err
	}
	for _, e := range evict {
		s.unindex(e)
	}
	s.index(sess)
	cp := *sess
	return secret, &cp, nil
}

// Lookup returns the live session for a cookie secret and refreshes its
// idle timer.
func (s *Store) Lookup(secret string) (*Session, error) {
	id := IDFromSecret(secret)
	now := s.opts.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	if !s.live(sess, now) {
		s.unindex(sess)
		return nil, ErrNotFound
	}
	sess.LastSeen = now
	if now.Sub(sess.persistedSeen) >= touchInterval {
		// A lost touch only makes a session expire earlier, so touches are
		// not fsynced and a failed touch does not fail the request.
		if err := s.append(false, record{Op: opTouch, ID: id, Time: now}); err == nil {
			sess.persistedSeen = now
		}
	}
	cp := *sess
	return &cp, nil
}

// Revoke ends the session with this public id. It returns false if no such
// live session exists. The session stops working immediately even if the
// log write fails; the error then says the revocation may not survive a
// restart.
func (s *Store) Revoke(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok {
		return false, nil
	}
	s.unindex(sess)
	return true, s.append(true, record{Op: opRevoke, ID: id})
}

// RevokeSubject ends every session of one user and returns how many. An
// empty provider matches the subject at every provider.
func (s *Store) RevokeSubject(provider, subject string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for k, set := range s.bySubject {
		p, sub, _ := strings.Cut(k, "\x00")
		if sub == subject && (provider == "" || p == provider) {
			for id := range set {
				ids = append(ids, id)
			}
		}
	}
	recs := make([]record, 0, len(ids))
	for _, id := range ids {
		recs = append(recs, record{Op: opRevoke, ID: id})
		s.unindex(s.byID[id])
	}
	if len(recs) == 0 {
		return 0, nil
	}
	return len(recs), s.append(true, recs...)
}

// List returns live sessions, oldest first. A non-empty subject filters to
// that user (any provider).
func (s *Store) List(subject string, limit int) []Session {
	now := s.opts.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Session
	for _, sess := range s.snapshot() {
		if !s.live(sess, now) || (subject != "" && sess.Identity.Subject != subject) {
			continue
		}
		out = append(out, *sess)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// Len returns the number of sessions held, including ones that expired
// since the last sweep.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byID)
}

// Sweep drops expired sessions from memory and compacts the log when it
// holds mostly dead records. Call it periodically.
func (s *Store) Sweep() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.opts.Now())
	if s.log != nil && s.log.records() > 2*len(s.byID)+compactSlack {
		return s.log.compact(s.snapshot())
	}
	return nil
}

func (s *Store) sweepLocked(now time.Time) {
	for _, sess := range s.byID {
		if !s.live(sess, now) {
			s.unindex(sess)
		}
	}
}

func (s *Store) append(sync bool, recs ...record) error {
	if s.log == nil {
		return nil
	}
	return s.log.append(sync, recs)
}
