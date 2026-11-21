# bench

The benchmark harness for the whole product (#86). This directory grows
over week 5: the load runner first, then seeded datasets, pinned competitor
setups, resource collection, the CI regression gate and the BENCHMARKS.md
report.

| Path | What it is |
| --- | --- |
| `cmd/authzbench` | Open-loop load runner for a mix of operations |
| `load` | The open-loop scheduler and its coordinated-omission correction |
| `hdr` | High dynamic range latency histogram (standard library only) |
| `ops` | The operations: checks, bulk checks, lookups, writes, forward-auth, OIDC login, MCP `tools/call` |
| `image-baseline.json` | Image size baseline for the CI image gate (week 1) |

## authzbench

```
go build -o authzbench ./bench/cmd/authzbench
AUTHZBENCH_API_KEY=... ./authzbench -api http://127.0.0.1:8080 \
  -mix check=70,bulk_check=10,lookup=10,write=10 \
  -rate 2000 -warmup 5s -duration 30s -workers 64 \
  -resources 1000 -subjects 1000 -out result.json
```

Operations and what each one checks in the answer:

| Name | Request | Counted as a success when |
| --- | --- | --- |
| `check` | `POST /v1/check` of `-permission` on a drawn resource for a drawn subject | 200 with a boolean `allowed` |
| `bulk_check` | `POST /v1/check/bulk` of `-bulk-items` drawn checks (1 to 100) | 200, every item answered in order, no item error |
| `lookup` | `POST /v1/lookup/resources` for a drawn subject, up to `-lookup-limit` | 200 with `resource_ids` |
| `write` | `POST /v1/relationships/write`, one `touch` of `-relation` | 200 with `written_at` |
| `forward_auth` | `GET -forward-url` with `X-Forwarded-Host/Uri/Method/Proto` and a session cookie | status `-forward-expect` (default 200) |
| `oidc_login` | a browser sign-in from `-login-start`: follow redirects, fill the first form with a password field, submit, follow redirects | the answers set `-login-cookie` |
| `mcp_call` | JSON-RPC `tools/call` of a drawn tool from `-mcp-tools` on `-mcp-url` | 200, a result for the request's id, not `isError`; JSON or event stream |

Resources are `-resource-type:-resource-prefix<n>` for n below `-resources`,
subjects `-subject-type:-subject-prefix<n>` for n below `-subjects`, drawn
uniformly or, with `-zipf s` (s above 1), so that low numbers are hot.
Forward-auth sessions come from `-sessions-file` (one `NAME=VALUE` per line),
from `-sessions N` sign-ins run before the load starts, or both. MCP calls
speak the 2026-07-28 revision with no session by default; `-mcp-protocol
2025-06-18` opens a session per worker with `initialize`, for gateways that
do not speak the newer revision. Keys come from the environment only
(`AUTHZBENCH_API_KEY`, `AUTHZBENCH_MCP_KEY`), so they never appear in a
process list or in the result file, which records the arguments.

### Method

The load is open loop. Send times are fixed before the run from `-rate`
(evenly spaced, or `-arrival poisson`) and `-seed`, and do not wait for
earlier answers, so a slow server cannot lower the load it is offered. Up
to `-workers` requests are in flight; due requests wait in a backlog of
`-backlog` (default four per worker) and then hold the scheduler.

Latency is measured from the time a request was **due**, not from when a
worker sent it. When the server stalls, every request due during the stall
is charged for its wait, which is the coordinated-omission correction of
wrk2 and HdrHistogram applied by construction. The time from the actual
send is reported as service time; the gap between the two is queueing in
the generator. A run that cannot keep up says so: the largest send lag is
printed, requests not sent within `-drain` of the end are `unsent`, and
requests still running then are cancelled and counted as errors.

Each worker records into its own histograms (three significant digits, 1 ns
to one minute, no allocation per record), merged when the run ends. The
result file holds p50, p90, p99, p99.9, max and mean per operation and for
the whole mix, both for latency and service time, with every histogram's
non-zero buckets, so runs can be merged or re-read by the report later.

The exit status is 0 when nothing was left unsent and failures stayed
within `-max-error-rate` (default 0.1%), 1 otherwise, and 2 for bad flags
or a failed setup.

### A first run

`authz serve` in memory with 1,000 documents shared through 50 groups of 20
users, the client and server on one 4 vCPU container, 2,000 requests per
second for 15 s after a 3 s warmup (the measured figures will come from the
pinned setups and datasets later this week):

```
   operation  requests  errors   per s  p50 ms  p90 ms  p99 ms  p99.9 ms   max ms  service p99 ms
       check     21044       0  1401.3   0.969   3.332   7.864    14.131   21.915           6.156
  bulk_check      3060       0   203.8   1.391   4.301   9.298    16.204   16.979           7.819
      lookup      2910       0   193.8  15.172  34.767  64.127    96.469  100.099          63.996
       write      2986       0   198.8   0.976   3.508   7.905    13.607   16.933           6.648
         all     30000       0  1997.7   1.159   7.377  34.439    63.308  100.099          33.686
offered 2000.0/s, achieved 1997.7/s; 30000 due, 30000 sent, 0 unsent; largest send lag 8.610324ms
```
