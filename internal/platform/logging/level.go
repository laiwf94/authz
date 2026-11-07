package logging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// ParseLevel reads a level the way the LOG_LEVEL variables do: debug, info,
// warn or error in any case, optionally with an offset such as "warn+2",
// as slog.Level.UnmarshalText accepts. Surrounding space is ignored.
func ParseLevel(s string) (slog.Level, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(strings.TrimSpace(s))); err != nil {
		return 0, fmt.Errorf("log level %q is not debug, info, warn or error", s)
	}
	return l, nil
}

// SetLevel parses s and sets lv to it, logging the change on log (when not
// nil) if the level moved. It returns the previous level.
func SetLevel(lv *slog.LevelVar, s string, log *slog.Logger) (slog.Level, error) {
	l, err := ParseLevel(s)
	if err != nil {
		return lv.Level(), err
	}
	old := lv.Level()
	lv.Set(l)
	if log != nil && old != l {
		// Logged at the higher of the two levels, so a change is seen
		// whichever way it goes.
		at := max(old, l, slog.LevelInfo)
		log.Log(context.Background(), at, "log level changed", "from", old.String(), "to", l.String())
	}
	return old, nil
}

// ReloadLevel sets lv from read each time reload receives, until ctx ends
// or reload is closed: wire it to SIGHUP with a read that re-reads the
// configuration. A read or parse error is logged and keeps the level.
func ReloadLevel(ctx context.Context, reload <-chan struct{}, lv *slog.LevelVar, read func() (string, error), log *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-reload:
			if !ok {
				return
			}
		}
		s, err := read()
		if err == nil {
			_, err = SetLevel(lv, s, log)
		}
		if err != nil && log != nil {
			log.Warn("log level not reloaded", "error", err.Error(), "level", lv.Level().String())
		}
	}
}

// maxLevelBody bounds a LevelHandler request body.
const maxLevelBody = 1 << 10

// LevelHandler serves lv for an admin API: GET answers {"level":"INFO"},
// PUT with {"level":"debug"} sets it and answers the new level. Changes are
// logged on log. It does no authentication; mount it behind the admin
// key check.
func LevelHandler(lv *slog.LevelVar, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
		case http.MethodPut:
			var body struct {
				Level *string `json:"level"`
			}
			dec := json.NewDecoder(io.LimitReader(r.Body, maxLevelBody+1))
			dec.DisallowUnknownFields()
			err := dec.Decode(&body)
			if err == nil && dec.More() {
				err = errors.New("trailing data")
			}
			if err == nil && body.Level == nil {
				err = errors.New(`missing "level"`)
			}
			if err == nil {
				_, err = SetLevel(lv, *body.Level, log)
			}
			if err != nil {
				writeLevelJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
		default:
			w.Header().Set("Allow", "GET, HEAD, PUT")
			writeLevelJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		writeLevelJSON(w, http.StatusOK, map[string]string{"level": lv.Level().String()})
	})
}

func writeLevelJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
