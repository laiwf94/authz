package keys

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Static key changes across SIGKILL. A child process issues and revokes
// keys as fast as it can, printing each change once the store returned it;
// the parent kills it at a random moment, reopens the file and requires it
// to hold exactly the acknowledged changes, or those and the one change
// the kill interrupted after its save, and never a torn file. Each round
// continues from the file the last one left.
func TestStaticKeysSurviveSIGKILL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "static-keys.json")
	rng := mrand.New(mrand.NewPCG(4, uint64(time.Now().UnixNano())))
	want := map[string]bool{} // digests of the issued keys acknowledged so far
	version := uint64(0)
	for round := range 12 {
		cmd := exec.Command(os.Args[0], "-test.run=^TestStaticKeysChild$", "-test.count=1")
		cmd.Env = append(os.Environ(), "STATIC_KEYS_CHILD="+path)
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		acks := make(chan string, 1<<16)
		go func() {
			sc := bufio.NewScanner(out)
			for sc.Scan() {
				acks <- sc.Text()
			}
			close(acks)
		}()
		// Let it run until it acknowledged a few changes, then a little more.
		started := time.After(10 * time.Second)
		var lines []string
	wait:
		for len(lines) < 3 {
			select {
			case l, ok := <-acks:
				if !ok {
					t.Fatalf("round %d: the child exited: %v", round, cmd.Wait())
				}
				lines = append(lines, l)
			case <-started:
				t.Fatalf("round %d: the child acknowledged nothing", round)
				break wait
			}
		}
		time.Sleep(time.Duration(rng.IntN(20_000)) * time.Microsecond)
		if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		_ = cmd.Wait()
		for l := range acks {
			lines = append(lines, l)
		}
		for _, l := range lines {
			f := strings.Fields(l)
			if len(f) != 3 {
				continue // test framework output
			}
			v, err := strconv.ParseUint(f[1], 10, 64)
			if err != nil || v != version+1 {
				t.Fatalf("round %d: acknowledged %q after version %d", round, l, version)
			}
			version = v
			switch f[0] {
			case "create":
				want[f[2]] = true
			case "revoke":
				if !want[f[2]] {
					t.Fatalf("round %d: revoked %s, which was never issued", round, f[2])
				}
				delete(want, f[2])
			}
		}

		s, err := OpenStatic(path)
		if err != nil {
			t.Fatalf("round %d: the file after the kill: %v", round, err)
		}
		if stale, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".static-keys.json.*")); len(stale) > 0 {
			t.Fatalf("round %d: temporary files left after opening: %v", round, stale)
		}
		got := map[string]bool{}
		_, list := s.List(nil, time.Now())
		for _, k := range list {
			got[hex.EncodeToString(k.SHA256[:])] = true
		}
		extra, missing := 0, 0
		for d := range got {
			if !want[d] {
				extra++
			}
		}
		for d := range want {
			if !got[d] {
				missing++
			}
		}
		switch v := s.Version(); {
		case v == version && extra == 0 && missing == 0:
		case v == version+1 && extra+missing == 1:
			// The kill came after the save and before the acknowledgement:
			// the change took effect, and the next round builds on it.
			version = v
			for d := range got {
				want[d] = true
			}
			for d := range want {
				if !got[d] {
					delete(want, d)
				}
			}
		default:
			t.Fatalf("round %d: file at version %d with %d extra and %d missing keys; acknowledged version %d",
				round, v, extra, missing, version)
		}
		t.Logf("round %d: %d changes acknowledged, file at version %d with %d keys", round, len(lines), s.Version(), len(got))
	}
}

func TestStaticKeysChild(t *testing.T) {
	path := os.Getenv("STATIC_KEYS_CHILD")
	if path == "" {
		t.Skip("run by TestStaticKeysSurviveSIGKILL")
	}
	s, err := OpenStatic(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		v, list := s.List(nil, time.Now())
		if len(list) > 40 || (len(list) > 0 && i%3 == 0) {
			k := list[mrand.IntN(len(list))]
			if _, nv, err := s.Revoke(v, nil, k.ID, time.Now()); err != nil {
				t.Fatal(err)
			} else {
				fmt.Fprintln(os.Stdout, "revoke", nv, hex.EncodeToString(k.SHA256[:]))
			}
			continue
		}
		var sum [32]byte
		rand.Read(sum[:])
		agent := "agent-" + strconv.Itoa(i%7)
		if n := slices.IndexFunc(list, func(k StaticKey) bool { return k.Agent == agent }); n >= 0 &&
			len(slices.DeleteFunc(slices.Clone(list), func(k StaticKey) bool { return k.Agent != agent })) >= MaxStaticKeysPerAgent {
			continue
		}
		if _, nv, err := s.Create(v, nil, agent, sum, time.Now()); err != nil {
			t.Fatal(err)
		} else {
			fmt.Fprintln(os.Stdout, "create", nv, hex.EncodeToString(sum[:]))
		}
	}
}
