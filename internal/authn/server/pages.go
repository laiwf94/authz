package server

import (
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"net/http"
	"strings"
)

// pageCSS is the only style on wicket's pages. The Content-Security-Policy
// allows exactly this stylesheet by hash and no scripts at all.
const pageCSS = `
:root{--bg:#f4f5f7;--card:#fff;--text:#1d2330;--muted:#5b6475;--line:#d9dde4;--accent:#2f5bd3;--danger:#b42318}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1d2128;--text:#e8eaee;--muted:#a3abb9;--line:#343a45;--accent:#7c9cf5;--danger:#f97066}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{width:100%;max-width:400px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:28px}
h1{font-size:20px;margin:0 0 8px}
p{margin:0 0 16px;color:var(--muted)}
.list{display:grid;gap:10px;margin:20px 0 0}
a.btn,button{display:block;width:100%;min-height:44px;padding:11px 14px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--text);font:inherit;text-align:center;text-decoration:none;cursor:pointer}
a.btn:hover,button:hover{border-color:var(--accent)}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.code{font:13px ui-monospace,monospace;color:var(--muted)}
.who{color:var(--text);font-weight:600}
`

// sessionsCSS is the sessions page's own addition to pageCSS. It is a
// second stylesheet, allowed only on that page (sessionsPolicy), so every
// other page and its policy stay byte for byte what the golden transcripts
// recorded.
const sessionsCSS = `
main.wide{max-width:560px}
ul.sessions{list-style:none;margin:20px 0 0;padding:0;display:grid;gap:12px}
ul.sessions li{border:1px solid var(--line);border-radius:8px;padding:14px}
ul.sessions p{margin:0 0 4px;font-size:14px}
ul.sessions form{margin-top:10px}
.tag{font-size:13px;color:var(--accent);font-weight:600}
button.danger{color:var(--danger)}
form.all{margin-top:20px}
`

func styleHash(css string) string {
	sum := sha256.Sum256([]byte(css))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

func cspWithStyles(css ...string) string {
	src := make([]string, len(css))
	for i, c := range css {
		src[i] = styleHash(c)
	}
	return "default-src 'none'; style-src " + strings.Join(src, " ") +
		"; form-action 'self' https:; frame-ancestors 'none'; base-uri 'none'"
}

var (
	contentSecurityPolicy = cspWithStyles(pageCSS)
	sessionsPolicy        = cspWithStyles(pageCSS, sessionsCSS)
)

var pages = template.Must(template.New("layout").Parse(`{{define "top"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer"><title>{{.Title}}</title><style>` + pageCSS + `</style></head><body><main>{{end}}
{{define "topwide"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer"><title>{{.Title}}</title><style>` + pageCSS + `</style><style>` + sessionsCSS + `</style></head><body><main class="wide">{{end}}
{{define "bottom"}}</main></body></html>{{end}}

{{define "choose"}}{{template "top" .}}
<h1>Sign in to continue</h1><p>Choose how you want to sign in.</p>
<div class="list">{{range .Providers}}<a class="btn" href="{{.URL}}">{{.Name}}</a>{{end}}</div>
{{template "bottom" .}}{{end}}

{{define "error"}}{{template "top" .}}
<h1>{{.Heading}}</h1><p>{{.Message}}</p>
{{if .Retry}}<div class="list"><a class="btn" href="{{.Retry}}">Try again</a></div>{{end}}
<p class="code">Reference: {{.RequestID}}</p>
{{template "bottom" .}}{{end}}

{{define "forbidden"}}{{template "top" .}}
<h1>You don't have access</h1>
<p>You are signed in as <span class="who">{{.User}}</span>, but this account is not allowed to use this application. Ask its owner for access, or sign in with another account.</p>
<form method="post" action="{{.LogoutURL}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><button type="submit">Sign out</button></form>
<p class="code">Reference: {{.RequestID}}</p>
{{template "bottom" .}}{{end}}

{{define "logout"}}{{template "top" .}}
<h1>Sign out?</h1><p>You are signed in as <span class="who">{{.User}}</span>.</p>
<form method="post" action="{{.LogoutURL}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="rd" value="{{.Return}}"><button class="primary" type="submit">Sign out</button></form>
{{template "bottom" .}}{{end}}

{{define "sessions"}}{{template "topwide" .}}
<h1>Your sessions</h1><p>Signed in as <span class="who">{{.User}}</span>. End any session you don't recognise.</p>
<ul class="sessions">{{range .Sessions}}<li>
<p class="who">{{.Device}}{{if .Current}} <span class="tag">This browser</span>{{end}}</p>
<p>Address {{.IP}}</p><p>Signed in {{.SignedIn}} · last used {{.LastUsed}}</p><p>Ends by {{.Ends}}</p>
<form method="post" action="{{$.EndURL}}"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="id" value="{{.ID}}"><button class="danger" type="submit">{{if .Current}}End this session and sign out{{else}}End session{{end}}</button></form>
</li>{{end}}</ul>
{{if .Others}}<form class="all" method="post" action="{{.EndURL}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="all" value="others"><button class="primary" type="submit">End all other sessions</button></form>{{end}}
{{template "bottom" .}}{{end}}

{{define "loggedout"}}{{template "top" .}}
<h1>You are signed out</h1><p>You can close this window.</p>
{{template "bottom" .}}{{end}}
`))

type providerLink struct{ Name, URL string }

func renderPage(w http.ResponseWriter, status int, name string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = pages.ExecuteTemplate(w, name, data)
}

func (s *Server) errorPage(w http.ResponseWriter, r *http.Request, status int, heading, msg, retry string) {
	renderPage(w, status, "error", map[string]any{"Title": heading, "Heading": heading, "Message": msg,
		"Retry": retry, "RequestID": requestIDFrom(r.Context())})
}
