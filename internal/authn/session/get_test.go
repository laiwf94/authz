package session

import (
	"path/filepath"
	"testing"
	"time"
)

// TestGetDoesNotTouch: Get finds a live session by its public handle
// without moving its idle timer, and finds nothing once it has ended.
func TestGetDoesNotTouch(t *testing.T) {
	c := &clock{t: time.Unix(1_000_000, 0)}
	s := open(t, filepath.Join(t.TempDir(), "s.log"), c)
	s.SetTimeouts(time.Hour, 24*time.Hour)
	_, sess, err := s.CreateWith(alice(), Extra{ACR: "urn:mfa", StepUp: "paths[1]"})
	if err != nil {
		t.Fatal(err)
	}
	c.add(30 * time.Minute)
	got, ok := s.Get(sess.ID)
	if !ok || got.ID != sess.ID || got.Identity.Subject != alice().Subject || got.Auth().ACR != "urn:mfa" ||
		got.StepUp() != "paths[1]" || !got.LastSeen.Equal(sess.LastSeen) {
		t.Fatalf("Get = %+v %v", got, ok)
	}
	// The copy is the caller's.
	got.Identity.Subject = "mallory"
	if again, _ := s.Get(sess.ID); again.Identity.Subject != alice().Subject {
		t.Fatal("Get returned the store's own session")
	}
	// Get did not refresh the idle timer: the session ends an hour after
	// it was last used.
	c.add(31 * time.Minute)
	if _, ok := s.Get(sess.ID); ok {
		t.Fatal("Get found a session past its idle timeout")
	}
	if _, ok := s.Get("00000000000000000000000000000000"); ok {
		t.Fatal("Get found an unknown session")
	}
	_, sess2, err := s.CreateWith(alice(), Extra{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Revoke(sess2.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get(sess2.ID); ok {
		t.Fatal("Get found a revoked session")
	}
}
