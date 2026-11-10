//go:build unix

package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseRotation(t *testing.T) {
	for _, tc := range []struct {
		bytes, age string
		want       Rotation
		err        string
	}{
		{"", "", Rotation{}, ""},
		{"0", "0", Rotation{}, ""},
		{"0", "0s", Rotation{}, ""},
		{"4096", "", Rotation{MaxBytes: 4096}, ""},
		{"", "24h", Rotation{MaxAge: 24 * time.Hour}, ""},
		{"67108864", "1m", Rotation{MaxBytes: 64 << 20, MaxAge: time.Minute}, ""},
		{"64MiB", "", Rotation{}, `"64MiB" is not a whole number of bytes`},
		{"1.5", "", Rotation{}, "not a whole number"},
		{"-1", "", Rotation{}, "must not be negative"},
		{"4095", "", Rotation{}, "size limit 4095 is under the minimum of 4096 bytes"},
		{"", "24", Rotation{}, `"24" is not a duration`},
		{"", "-1h", Rotation{}, "must not be negative"},
		{"", "59s", Rotation{}, "age limit 59s is under the minimum of 1m0s"},
	} {
		got, err := ParseRotation(tc.bytes, tc.age)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("ParseRotation(%q, %q) = %v, want an error with %q", tc.bytes, tc.age, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("ParseRotation(%q, %q) = %+v, %v; want %+v", tc.bytes, tc.age, got, err, tc.want)
		}
	}
}

func TestRotationString(t *testing.T) {
	for r, want := range map[Rotation]string{
		{}:                                  "no rotation",
		{MaxBytes: 4096}:                    "max_bytes=4096",
		{MaxAge: time.Hour}:                 "max_age=1h0m0s",
		{MaxBytes: 4096, MaxAge: time.Hour}: "max_bytes=4096 max_age=1h0m0s",
	} {
		if got := r.String(); got != want {
			t.Errorf("%+v: %q, want %q", r, got, want)
		}
	}
}

// firstStart returns the segment start record the active file opens with.
func firstStart(t *testing.T, path string) SegmentStarted {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line, _, _ := strings.Cut(string(b), "\n")
	var r Record
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		t.Fatal(err)
	}
	if r.Event != EventSegmentStarted {
		t.Fatalf("first record is %s", r.Event)
	}
	var ss SegmentStarted
	if err := json.Unmarshal(r.Data, &ss); err != nil {
		t.Fatal(err)
	}
	return ss
}

// A segment start record carries the rotating writer's limits, and the
// chain still verifies against the schemas.
func TestSegmentStartRecordsLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	c := newClock()
	r := Rotation{MaxBytes: MinRotateBytes, MaxAge: 2 * time.Hour}
	l := openRotating(t, path, r, c.now)
	for i := 0; i < 40; i++ {
		if err := l.Append("tool_call", callRec(i)); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	ss := firstStart(t, path)
	if ss.Reason != RotateSize || ss.MaxBytes != MinRotateBytes || ss.MaxAge != "2h0m0s" {
		t.Fatalf("segment start %+v", ss)
	}
	if _, err := VerifyChain(path, Default()); err != nil {
		t.Fatal(err)
	}

	// A writer without limits records none.
	path2 := filepath.Join(t.TempDir(), "audit.jsonl")
	l2 := openRotating(t, path2, Rotation{}, c.now)
	l2.Append("tool_call", callRec(1))
	if err := l2.Rotate(); err != nil {
		t.Fatal(err)
	}
	l2.Close()
	if ss := firstStart(t, path2); ss.Reason != RotateManual || ss.MaxBytes != 0 || ss.MaxAge != "" {
		t.Fatalf("segment start %+v", ss)
	}
	b, _ := os.ReadFile(path2)
	if strings.Contains(string(b), "max_") {
		t.Fatalf("limits written for a writer without any: %s", b)
	}
}

// With SameRotation, a writer whose limits differ from those the active
// segment was cut under is refused; the same limits, a writer without
// SameRotation and segments that record no limits are not.
func TestOpenSameRotation(t *testing.T) {
	c := newClock()
	mine := Rotation{MaxBytes: MinRotateBytes}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := openRotating(t, path, mine, c.now)
	for i := 0; i < 40; i++ {
		l.Append("tool_call", callRec(i))
	}
	l.Close()

	for _, other := range []Rotation{{}, {MaxBytes: 2 * MinRotateBytes}, {MaxBytes: MinRotateBytes, MaxAge: time.Hour}} {
		_, err := OpenWith(path, Options{Now: c.now, Rotation: other, SameRotation: true})
		want := "is rotated with max_bytes=4096, but this writer has " + other.String()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: open: %v, want %q", other, err, want)
		}
	}
	for _, o := range []Options{
		{Now: c.now, Rotation: mine, SameRotation: true},
		{Now: c.now, Rotation: Rotation{MaxAge: time.Hour}},
	} {
		l, err := OpenWith(path, o)
		if err != nil {
			t.Fatalf("%+v: %v", o, err)
		}
		l.Close()
	}

	// The chain's first segment, a manual rotation and a record without
	// limits leave the writer free.
	fresh := filepath.Join(t.TempDir(), "audit.jsonl")
	l = openRotating(t, fresh, Rotation{}, c.now)
	l.Append("tool_call", callRec(1))
	l.Close()
	if l, err := OpenWith(fresh, Options{Now: c.now, Rotation: mine, SameRotation: true}); err != nil {
		t.Fatal(err)
	} else if err := l.Rotate(); err != nil {
		t.Fatal(err)
	} else {
		l.Close()
	}
	if l, err := OpenWith(fresh, Options{Now: c.now, Rotation: Rotation{MaxAge: time.Hour}, SameRotation: true}); err != nil {
		t.Fatalf("after a manual rotation: %v", err)
	} else {
		l.Close()
	}
	for _, ss := range []*SegmentStarted{
		nil,
		{Reason: RotateManual, MaxBytes: 1 << 20},
		{Reason: RotateSize},
		{Reason: RotateAge, MaxAge: "1h0m0s"},
	} {
		if err := CheckSameRotation("x", ss, Rotation{MaxAge: time.Hour}); err != nil {
			t.Errorf("%+v: %v", ss, err)
		}
	}
	if err := CheckSameRotation("x", &SegmentStarted{Reason: RotateAge, MaxAge: "an hour"}, Rotation{}); err == nil ||
		!strings.Contains(err.Error(), `max_age "an hour", not a duration`) {
		t.Errorf("malformed max_age: %v", err)
	}
}

func TestRotationFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	r, err := RotationFromEnv(env(map[string]string{"B": "8192", "A": "1h"}), "B", "A")
	if err != nil || r != (Rotation{MaxBytes: 8192, MaxAge: time.Hour}) {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := RotationFromEnv(env(nil), "B", "A"); err != nil || r.Enabled() {
		t.Fatalf("unset: %+v %v", r, err)
	}
	for m, want := range map[[2]string]string{
		{"x", ""}:   `B: size limit "x" is not a whole number of bytes`,
		{"100", ""}: "B: size limit 100 is under the minimum",
		{"", "1d"}:  `A: age limit "1d" is not a duration such as 24h`,
		{"", "1s"}:  "A: age limit 1s is under the minimum",
	} {
		_, err := RotationFromEnv(env(map[string]string{"B": m[0], "A": m[1]}), "B", "A")
		if err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("%v: %v, want %q", m, err, want)
		}
	}
}
