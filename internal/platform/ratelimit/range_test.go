package ratelimit

import (
	"math"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCutAndSplitKey(t *testing.T) {
	for _, dims := range [][]string{
		{"a"}, {""}, {"", ""}, {"a:b", "c"}, {"a", "b:c"}, {"10:x", "", "3:abc"},
		{strings.Repeat("z", 1234), "agent"}, {Key("rule", "r1", "2"), "alice-bot"},
	} {
		key := Key(dims...)
		got, ok := SplitKey(key)
		if !ok || !slices.Equal(got, dims) {
			t.Errorf("SplitKey(%q) = %q, %v; want %q", key, got, ok, dims)
		}
		first, rest, ok := CutKey(key)
		if !ok || first != dims[0] || rest != Key(dims[1:]...) {
			t.Errorf("CutKey(%q) = %q, %q, %v", key, first, rest, ok)
		}
	}
	if dims, ok := SplitKey(""); !ok || dims != nil {
		t.Errorf("SplitKey of the empty key: %q, %v", dims, ok)
	}
	// Keys that do not start with a dimension.
	for _, bad := range []string{
		"", ":", "a", "1", "1:", "2:a", ":a", "-1:a", "+1:a", "01:a", "1a:b", "x:y",
		"9999999999999999999:a", "1234567890123456789:a",
	} {
		if _, _, ok := CutKey(bad); ok {
			t.Errorf("CutKey(%q) accepted it", bad)
		}
		if dims, ok := SplitKey(bad); ok && bad != "" {
			t.Errorf("SplitKey(%q) = %q", bad, dims)
		}
	}
	// Keys that start with one but do not go on with another.
	for _, bad := range []string{"1:a2:b", "1:a:", "1:ax"} {
		if _, _, ok := CutKey(bad); !ok {
			t.Errorf("CutKey(%q) refused its first dimension", bad)
		}
		if dims, ok := SplitKey(bad); ok {
			t.Errorf("SplitKey(%q) = %q", bad, dims)
		}
	}
}

func FuzzSplitKey(f *testing.F) {
	for _, s := range []string{"", "1:a", "3:abc0:", "01:a", "2:ab1:", "5:a:b:c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, key string) {
		dims, ok := SplitKey(key)
		if !ok {
			return
		}
		// A key that splits is exactly the key of its dimensions.
		if again := Key(dims...); again != key {
			t.Fatalf("SplitKey(%q) = %q, which joins to %q", key, dims, again)
		}
	})
}

func TestRange(t *testing.T) {
	t0 := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	clk, l := newFake(t0, 0)
	lim := Limit{Rate: 2, Burst: 4} // a token every 500ms
	for range 3 {
		l.Take("a", lim)
	}
	l.Take("b", lim)
	l.Take("c", Limit{}) // unlimited: no entry
	seen := map[string]time.Duration{}
	l.Range(func(k string, debt time.Duration) bool { seen[k] = debt; return true })
	if len(seen) != 2 || seen["a"] != 1500*time.Millisecond || seen["b"] != 500*time.Millisecond {
		t.Fatalf("Range: %v", seen)
	}
	for k, debt := range seen {
		if tok, _ := l.Tokens(k, lim); tok != lim.TokensAt(debt) {
			t.Errorf("%s: Tokens %v, TokensAt %v", k, tok, lim.TokensAt(debt))
		}
	}
	// A refilled bucket is the same as no entry, swept or not.
	clk.add(600 * time.Millisecond)
	clear(seen)
	l.Range(func(k string, debt time.Duration) bool { seen[k] = debt; return true })
	if len(seen) != 1 || seen["a"] != 900*time.Millisecond {
		t.Fatalf("after 600ms: %v", seen)
	}
	// fn returning false stops the walk.
	l.Take("b", lim)
	calls := 0
	l.Range(func(string, time.Duration) bool { calls++; return false })
	if calls != 1 {
		t.Fatalf("Range went on after false: %d calls", calls)
	}
}

func TestTokensAt(t *testing.T) {
	lim := Limit{Rate: 4, Burst: 2} // a token every 250ms
	for _, tc := range []struct {
		debt time.Duration
		want float64
	}{{0, 2}, {-time.Second, 2}, {125 * time.Millisecond, 1.5}, {500 * time.Millisecond, 0}, {time.Hour, 0}} {
		if got := lim.TokensAt(tc.debt); got != tc.want {
			t.Errorf("TokensAt(%v) = %v, want %v", tc.debt, got, tc.want)
		}
	}
	if !math.IsInf(Limit{}.TokensAt(time.Second), 1) {
		t.Error("an unlimited bucket should hold +Inf")
	}
	if (Limit{Rate: 1}).TokensAt(0) != 1 {
		t.Error("a burst below 1 holds 1")
	}
}

func TestDailyRange(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Fatal(err)
	}
	// 22:30 UTC is 23:30 in Berlin (UTC+1): Berlin's day ends at 23:00 UTC,
	// UTC's at midnight.
	// Berlin is UTC+1, so its day ends at 23:00 UTC and UTC's at 00:00 UTC.
	clk, q := newDaily(time.Date(2026, 11, 28, 22, 30, 0, 0, time.UTC), 0)
	q.Take("berlin", 10, loc)
	q.Take("berlin", 10, loc)
	q.Take("utc", 10, time.UTC)
	q.Take("refunded", 10, time.UTC)
	q.Refund("refunded")
	type entry struct {
		n   int
		end time.Time
	}
	read := func() map[string]entry {
		m := map[string]entry{}
		q.Range(func(k string, n int, end time.Time) bool { m[k] = entry{n, end}; return true })
		return m
	}
	got := read()
	want := map[string]entry{
		"berlin": {2, time.Date(2026, 11, 28, 23, 0, 0, 0, time.UTC)},
		"utc":    {1, time.Date(2026, 11, 29, 0, 0, 0, 0, time.UTC)},
	}
	if len(got) != len(want) || !got["berlin"].end.Equal(want["berlin"].end) || got["berlin"].n != 2 ||
		!got["utc"].end.Equal(want["utc"].end) || got["utc"].n != 1 {
		t.Fatalf("Range: %v, want %v", got, want)
	}
	// Berlin's day has ended; the entry is not swept yet but is not reported.
	clk.add(45 * time.Minute)
	if got := read(); len(got) != 1 || got["utc"].n != 1 {
		t.Fatalf("after Berlin's midnight: %v", got)
	}
	if q.Len() != 3 {
		t.Fatalf("Len %d: Range should not sweep", q.Len())
	}
	q.Take("x", 10, time.UTC)
	calls := 0
	q.Range(func(string, int, time.Time) bool { calls++; return false })
	if calls != 1 {
		t.Fatalf("Range went on after false: %d calls", calls)
	}
}
