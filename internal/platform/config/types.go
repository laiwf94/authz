package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Duration is a time.Duration written as a Go duration string ("8h").
type Duration time.Duration

// MarshalJSON writes the duration as a string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON parses "90s", "8h" and so on. Negative durations are
// refused.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New(`durations are strings like "90s" or "8h"`)
	}
	v, err := parseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func parseDuration(s string) (time.Duration, error) {
	v, err := time.ParseDuration(s)
	if err != nil || v < 0 {
		return 0, fmt.Errorf(`invalid duration %q (use a string like "90s" or "8h")`, s)
	}
	return v, nil
}

// MaxSecretBytes bounds a secret file.
const MaxSecretBytes = 64 << 10

// Secret is a value that is never written in the configuration file. The
// file names where it is instead, as {"file": "/run/secrets/api-keys"} or
// {"env": "API_KEYS"}; loading reads it, trimming surrounding white space.
// An environment override sets it directly (AUTHZ_SERVE_API_KEYS=...) or
// names a file (AUTHZ_SERVE_API_KEYS_FILE=...).
//
// String and GoString never show the value, so a Secret can be logged.
type Secret struct {
	Env  string `json:"env,omitempty"`
	File string `json:"file,omitempty"`

	value  string
	direct bool // set by an environment override, not a reference
}

// Value returns the secret. It is empty for a Secret that was not set.
func (s Secret) Value() string { return s.value }

// IsSet reports whether the configuration gave the secret.
func (s Secret) IsSet() bool { return s.Env != "" || s.File != "" || s.direct }

// String describes where the secret came from, never its value.
func (s Secret) String() string {
	switch {
	case s.File != "":
		return "secret(file " + s.File + ")"
	case s.Env != "":
		return "secret(env " + s.Env + ")"
	case s.direct:
		return "secret(set)"
	}
	return "secret(unset)"
}

// GoString is String, so %#v does not print the value either.
func (s Secret) GoString() string { return s.String() }
