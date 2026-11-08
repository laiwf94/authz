package httpserver

import (
	"errors"
	"fmt"
	"time"
)

// FromEnv reads a subcommand's TLS and drain settings from its variables:
// prefix+"TLS_CERT", "TLS_KEY", "TLS_CLIENT_CA", "DRAIN_DELAY" and
// "DRAIN_TIMEOUT". Unset variables keep the defaults: plain HTTP, no delay
// and DefaultDrainTimeout.
func FromEnv(getenv func(string) string, prefix string) (Options, error) {
	var o Options
	cert, key, ca := getenv(prefix+"TLS_CERT"), getenv(prefix+"TLS_KEY"), getenv(prefix+"TLS_CLIENT_CA")
	switch {
	case cert != "" && key != "":
		o.TLS = &TLSFiles{CertFile: cert, KeyFile: key, ClientCAFile: ca}
	case cert != "" || key != "":
		return o, fmt.Errorf("%sTLS_CERT and %sTLS_KEY must be set together", prefix, prefix)
	case ca != "":
		return o, fmt.Errorf("%sTLS_CLIENT_CA needs %sTLS_CERT and %sTLS_KEY", prefix, prefix, prefix)
	}
	var err error
	if o.DrainDelay, err = envDuration(getenv, prefix+"DRAIN_DELAY", 0); err != nil {
		return o, err
	}
	if o.DrainTimeout, err = envDuration(getenv, prefix+"DRAIN_TIMEOUT", DefaultDrainTimeout); err != nil {
		return o, err
	}
	if o.DrainTimeout == 0 {
		return o, errors.New(prefix + "DRAIN_TIMEOUT must be more than 0s")
	}
	return o, nil
}

func envDuration(getenv func(string) string, name string, def time.Duration) (time.Duration, error) {
	v := getenv(name)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if v == "0" {
		d, err = 0, nil
	}
	if err != nil || d < 0 || d > time.Hour {
		return 0, fmt.Errorf("%s must be a duration from 0s to 1h, such as 20s", name)
	}
	return d, nil
}
