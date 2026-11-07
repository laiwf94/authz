package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laiwf94/authz/internal/authn/config"
	"github.com/laiwf94/authz/internal/authn/server"
	"github.com/laiwf94/authz/internal/authn/session"
	"github.com/laiwf94/authz/internal/platform/jose"
	"github.com/laiwf94/authz/internal/platform/metrics"
	"github.com/laiwf94/authz/internal/platform/seal"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/golden from the current responses")

// inProcess runs the gateway's handlers from server.New on TLS test
// listeners, the way the transcripts were first recorded.
func inProcess(t *testing.T, o Options, adminToken string) (*Env, Target) {
	t.Helper()
	pub := httptest.NewUnstartedServer(nil)
	admin := httptest.NewUnstartedServer(nil)
	e := NewEnv(t, pub.Listener.Addr().String(), o)
	sessions, err := session.Open(session.Options{Now: e.Clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sessions.Close() })
	keys, _ := seal.New([][]byte{seal.RandomKey()})
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jose.NewSigner(ek)
	srv, err := server.New(server.Options{
		Load:     func() (*config.Config, error) { return config.Load(e.ConfigPath, e.Getenv) },
		Sessions: sessions, Keys: keys, Signers: []*jose.Signer{signer},
		Logger:  slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Metrics: metrics.New(), AdminToken: adminToken, LoginRate: 10_000, Now: e.Clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	pub.Config.Handler = srv.Handler()
	pub.StartTLS()
	t.Cleanup(pub.Close)
	admin.Config.Handler = srv.AdminHandler()
	admin.Start()
	t.Cleanup(admin.Close)
	return e, Target{Admin: admin.URL, Transport: pub.Client().Transport}
}

func TestGolden(t *testing.T) {
	for _, sc := range Scenarios {
		t.Run(sc.File, func(t *testing.T) {
			token := ""
			if sc.AdminToken {
				token = AdminToken
			}
			e, tg := inProcess(t, sc.Options, token)
			g := NewRecorder(t, e, tg)
			sc.Run(g)
			Check(t, filepath.Join("testdata", "golden", sc.File), g.Bytes(), *updateGolden)
		})
	}
}

// A changed response fails the replay with a diff naming the line.
func TestGoldenCatchesChange(t *testing.T) {
	e, tg := inProcess(t, Options{}, "")
	g := NewRecorder(t, e, tg)
	oidcLogin(g)
	got := strings.Replace(string(g.Bytes()), "X-Frame-Options: DENY", "X-Frame-Options: SAMEORIGIN", 1)
	ft := &fakeT{TB: t}
	func() {
		defer func() { _ = recover() }()
		Check(ft, filepath.Join("testdata", "golden", "oidc.txt"), []byte(got), false)
	}()
	if !ft.failed || !strings.Contains(ft.msg, "SAMEORIGIN") {
		t.Fatalf("changed transcript not reported: failed=%v %q", ft.failed, ft.msg)
	}
}

// fakeT records a Fatal instead of failing the test.
type fakeT struct {
	testing.TB
	failed bool
	msg    string
}

func (f *fakeT) Helper() {}
func (f *fakeT) Fatal(args ...any) {
	f.failed = true
	for _, a := range args {
		if err, ok := a.(error); ok {
			f.msg += err.Error()
		}
	}
	panic("fatal")
}

func TestPlainHTTP(t *testing.T) {
	var scheme []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme = append(scheme, r.URL.Path)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	c := &http.Client{Transport: PlainHTTP(host)}
	for _, u := range []string{"https://" + host + "/tls", srv.URL + "/plain"} {
		resp, err := c.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if strings.Join(scheme, ",") != "/tls,/plain" {
		t.Fatalf("got %v", scheme)
	}
}

func TestFormFields(t *testing.T) {
	action, f := FormFields(`<form method="post" action="/a?x=1&amp;y=2"><input type="hidden" name="k" value="v&amp;w"></form>`)
	if action != "/a?x=1&y=2" || f.Get("k") != "v&w" {
		t.Fatalf("%q %v", action, f)
	}
	if action, f := FormFields("none"); action != "" || len(f) != 0 {
		t.Fatalf("%q %v", action, f)
	}
}
