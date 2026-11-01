# authz roadmap, November 2026 to October 2027

## Vision

By October 2027 authz is one Go identity and access platform, built from grantd, wicket and toolgate, that does three jobs in one small binary: it signs people and agents in (OpenID Connect and SAML provider and relying party, passkeys, MFA, flows, federation, SCIM, organizations), it decides what they may do (Zanzibar-style relationships with caveats, attributes, every query, consistency tokens, a disk store, PostgreSQL, MySQL and CockroachDB, a Raft-replicated and sharded cluster), and it governs what AI agents do through MCP (default-deny tool policy, approvals, data-flow labels, sandboxes, a credential vault, a tamper-evident audit chain). It targets parity with Okta, Auth0, Microsoft Entra ID, Ping Identity, Keycloak, Zitadel, Ory and FusionAuth on identity, with Okta FGA, AuthZed SpiceDB, OpenFGA, Permit.io and Cerbos on authorization, and with Kong AI Gateway, Azure API Management, Cloudflare MCP portals, agentgateway and IBM ContextForge on agent traffic, and goes further where only a combined product can: the gateway and the MCP proxy ask the authorization engine in process, agents are directory principals with owners and delegated tokens, and every sign-in, permission change and tool call lands in one Merkle-provable audit chain. It stays lightweight: one static binary and an image under 25 MB, idle memory under 30 MB, cold start under 100 ms, check p99 under 5 ms at 100 million relationships, forward-auth and MCP added p99 under 1 ms, published in a reproducible benchmark against the leaders, re-measured every quarter and held by a CI regression gate. The server is Go on the standard library first; the admin console and the JavaScript SDK are TypeScript.

Benchmark products: Okta, Auth0, Microsoft Entra ID, Ping Identity, Keycloak, Zitadel, Ory, FusionAuth, Authentik and oauth2-proxy for identity; Okta FGA, AuthZed SpiceDB, OpenFGA, Permit.io, Cerbos, OPA and Oso for authorization; Kong AI Gateway, Azure API Management, Cloudflare MCP server portals, agentgateway, IBM ContextForge, Docker MCP Gateway and Lasso for agent traffic.

Footprint and speed targets, published in BENCHMARKS.md from week 5, re-measured in weeks 22, 34, 44 and 52 and enforced by the CI gate: image under 25 MB, idle RSS under 30 MB with all subcommands, cold start under 100 ms, check p99 under 5 ms at 100 million relationships, forward-auth p99 under 1 ms, MCP added p99 under 1 ms, 64 MB resident with 100,000 sessions.

## How the year runs

Every week ships three features in parallel, one per track, each run as one half-day cloud task per day (seven tasks a week, the last an end-to-end demo plus docs):

- **authn** (from wicket): sign-in, the identity provider, OIDC and SAML, passkeys, MFA, sessions, directories, SCIM, tenants, admin access and the console.
- **authz** (from grantd): relationships, schema, checks, lookups, storage, clustering, and the platform pieces that sit under storage: replication, Raft, backups, encryption, upgrades, benchmarks and SDKs.
- **agents** (from toolgate): the MCP gateway, agent identity and delegation, tool policy, approvals, guardrails, sandboxes, and the platform pieces that sit around events: audit, event delivery, observability, releases, rate limits and metering.

The three features of a week are planned to touch different packages, apart from the week 1 and 2 moves. Where one track needs another's work, the dependency points backwards in time (for example agents week 5 uses the in-process engine from authz week 3 and the CEL engine from authz week 4).

## Layout

```text
authz/
  cmd/authz/            one binary: serve, gateway, mcp, ctl, check, backup, restore, fakeidp, mcpfake
  internal/platform/    config, logging, metrics, telemetry, httpserver, storage, raft, cluster, keys, jose,
                        seal, crypt, audit, events, ratelimit, tenant, cel, backup, importer, sim, format
  internal/authz/       relationships (was grantd/internal)
  internal/authn/       sign-in (was wicket/internal)
  internal/agents/      agent traffic (was toolgate/internal)
  pkg/                  middleware, verify, agents, mcpauth (public Go API)
  console/              TypeScript admin console and account portal, embedded in the binary
  sdk/                  go, typescript, python, java, dotnet, ruby, plus the shared scenario file
  api/openapi.yaml      one description of all three HTTP APIs
  bench/                benchmark harness, competitor setups, thresholds for the CI gate
  deploy/               Helm chart, operator, Gateway API, monitoring, reference deployment
  .github/workflows/    ci.yml (the one gate), bench.yml, interop.yml, release.yml
```

| Package | Purpose |
|---|---|
| cmd/authz | The one binary: serve (checks API), gateway (forward-auth and identity provider), mcp (agent gateway), ctl, check, backup, restore and operator helpers as subcommands |
| internal/platform/config | One versioned config schema for every subcommand, secret file references and live reload, validated by `authz check` |
| internal/platform/logging | log/slog handler with correlation IDs, tenant attributes and redaction of secret fields |
| internal/platform/metrics | One metrics registry with cardinality caps and Prometheus exposition |
| internal/platform/telemetry | OTLP/HTTP span and metric export written on the standard library |
| internal/platform/storage, segment, diskstore, replication | Store interfaces, the shared write-ahead log with group commit, the disk store (sorted segments, compaction), the replication stream and storetest conformance |
| internal/platform/raft | The one Raft implementation: election, replication, snapshots, membership and linearizable reads |
| internal/platform/cluster | Replicated state machine carrying every track's state, follower reads, multi-region learners, multi-Raft ranges and cross-range transactions |
| internal/platform/pgwire, pgstore, mysqlwire, mysqlstore | PostgreSQL, CockroachDB and MySQL backends over in-house wire protocol clients |
| internal/platform/keys, jose, seal, crypt, tlsconf | Key rings with rotation and JWKS, JOSE, sealed cookies, envelope encryption with tenant keys, TLS and mutual TLS with reload, and a FIPS build |
| internal/platform/audit, merkle, export | The one hash-chained audit log with signed checkpoints, RFC 6962 proofs, query, shipping, and OCSF, CEF and syslog export |
| internal/platform/events | Subscriptions and signed webhook delivery for audit events and the relationship change feed |
| internal/platform/ratelimit | GCRA limiter for logins, keys, agents and tools, with cluster-wide leases |
| internal/platform/tenant | Tenant and organization context resolved once per request and enforced in every store |
| internal/platform/cel | One CEL-subset engine for relationship caveats, attribute rules, flow conditions, claims and tool policy |
| internal/platform/httpserver | Listeners, TLS, timeouts, header limits, readiness and graceful drain for every subcommand |
| internal/platform/backup, objstore, importer, sim, format, mem, erase, clock | Backups and point-in-time restore, object store client, resumable import framework, deterministic simulation, on-disk format versioning, memory budgets, subject erasure and an injectable clock |
| internal/platform/protowire, grpcsrv | In-house protobuf encoding and gRPC framing shared by the SpiceDB-compatible API and gRPC tools |
| internal/authz/* | Relationships: engine (in-process API), check, schema, store, token, lookup, dispatch, leopard index, shard, placement, whatif, review, history, filter, policyimport, spicecompat, fgacompat, extauthz, local decision point |
| internal/authn/* | Sign-in: oidc and saml relying parties, op (OpenID provider), samlidp, directory, password, webauthn, mfa, flow, broker, ldap, scim, provision, risk, access (conditional access), ssf, vc, sshca, session, policy (route rules) |
| internal/agents/* | Agent traffic: mcp, jsonrpc, gateway, policy, approval, pins, inspect, guardrail, flow (labels), vault, vserver, toolsearch, sandbox, container, registry, a2a, llm, retrieval, anomaly, incident, recording |
| console/ | TypeScript admin console and account portal (Lit Web Components, Vite build) embedded in the binary |
| sdk/go, sdk/typescript, sdk/python, sdk/java, sdk/dotnet, sdk/ruby | Clients generated from api/openapi.yaml, with token verification helpers and a shared conformance scenario file |
| pkg/middleware, pkg/verify, pkg/agents, pkg/mcpauth | Public Go packages: check middleware, token and call-assertion verification, the embeddable agent pipeline, MCP server auth middleware |
| bench/ | One benchmark harness against SpiceDB, OpenFGA, Keycloak, Zitadel, oauth2-proxy, agentgateway and Kong, with the CI regression gate |
| deploy/ | Helm chart, AuthzCluster operator, Gateway API integration, monitoring rules and the reference deployment |

Dependencies: the server is standard library first. Named exceptions, each justified in the week that adds it: beevik/etree and russellhaering/goxmldsig for SAML XML signatures (carried from wicket, week 1), golang.org/x/crypto for argon2id and SSH certificates (authn weeks 8 and 51), jcmturner/gokrb5 for Kerberos (authn week 43, confined to one package), and HashiCorp's terraform-plugin-framework in the separate terraform-provider-authz module (authn week 18). jonboulle/clockwork is removed in week 2. PostgreSQL, MySQL, protobuf, gRPC framing, OTLP, ACME, LDAP, RADIUS, WebAuthn and the object store client are written in-house. The console uses Lit and Vite; the TypeScript SDK has no runtime dependency.

## Weeks 1 and 2: one product without behaviour change

The rename of grantd to authz and the subtree import of wicket and toolgate (full history, own go.mod files) are the starting point. Go's internal package rule stops the root binary from importing wicket/internal or toolgate/internal, so week 1 moves the trees rather than wrapping them.

- **Week 1, all three tracks:** one go.mod at the root; grantd code to internal/authz, wicket to internal/authn, toolgate to internal/agents, with a script that rewrites only import specs; one `authz` binary whose subcommands (serve, gateway, mcp, fakeidp, mcpfake) keep the old flags, environment variables and config files; one CI gate replacing three workflows. Proof of no behaviour change: scripts/testbody-diff.sh shows zero changed lines in any test body outside import blocks and package clauses (except relative fixture paths that the extra directory level forces, each listed in the week's issue; the package clause changes because each old `package main` becomes its own subcommand package under cmd/authz/internal, since grantd, wicket, fakeidp, toolgate and mcpfake all define `run`, `env` or `loadConfig` and their test bodies could not share one package unchanged), test counts per package match the pre-merge counts, and golden responses (wicket) and recorded decisions (toolgate) diff empty.
- **Week 2, split by track:** authz extracts the storage log, the metrics registry and the HTTP server; authn extracts the key service, JOSE, sealed cookies and one config schema with live reload; agents extracts the audit log, structured logging with correlation IDs and the rate limiter. Each old crash, rotation and limiter test passes against the shared package unchanged.
- **Week 3 onward:** integration that only a combined product can do. The gateway and the MCP proxy call the engine in process (authz week 3, authn week 4, agents week 5), agents get identities and delegated tokens from authn (weeks 15 and 16), and every event lands in one audit chain (agents week 3).

## Shared capabilities, owned once

The three earlier plans each planned the items below. Each now appears once, in the track named; the freed slots went to new parity work (Shared Signals, workload identity federation, conditional access, verifiable credentials, Kerberos, LDAP and RADIUS front-ends, push MFA, data filtering, Cedar and Rego import, .NET and Ruby SDKs, schema modules, Cross App Access, retrieval authorization, LLM routing, code mode, delegation chains and more).

| Capability | Planned in | Owner track | Weeks | How the other tracks use it |
|---|---|---|---|---|
| Raft-replicated store and automatic failover | grantd w13-14, wicket w41, toolgate w38-41 | authz | w13, w14 | sessions, directory, approvals, pins and limits are state machines on the one cluster |
| Read replicas and shared replica state | grantd w7, wicket w5, toolgate w7 | authz | w8 | forward-auth and MCP followers answer locally |
| Storage engine, disk store, group commit | grantd w2, w6; wicket w13; toolgate w13 | authz | w2, w6, w7 | one store interface for every track |
| PostgreSQL, MySQL, CockroachDB | grantd w17-18, wicket w14 | authz | w17, w18 | directory and sessions get tables in the same backends |
| Multi-region | grantd w31, wicket w42, toolgate w42 | authz | w29 | sign-in and gateway reads use WAN learners |
| Backups, point-in-time restore, DR | grantd w4, wicket w42, toolgate w43 | authz | w30 | one snapshot at one revision covers every track |
| Encryption at rest, FIPS | grantd w28, wicket w31, toolgate w13 | authz | w27 | per-tenant data keys for every keyspace |
| Upgrades and format versioning | grantd w43, wicket w46, toolgate w52 | authz | w40 | directory, session and audit formats registered there |
| Simulation and fault injection | grantd w12, w44; toolgate w38, w41 | authz | w41 | invariants for sessions and single-use approvals included |
| Benchmark harness and CI gate | grantd w5, w22, w35, w48, w52; wicket w9, w22, w35, w44, w52; toolgate w10, w26, w44, w51 | authz | w5; re-runs w22, w34, w44, w52 | hot path work stays per track: check engine authz w12, identity paths authn w30, MCP path agents w11 |
| Memory footprint and cold start | grantd w45, wicket w45, toolgate w44 | authz | w42 | one budget for the one binary |
| SDKs | grantd w10, w24; wicket w12, w49; toolgate w49 | authz | w10, w23, w24, w48 | generated from one api/openapi.yaml covering all three APIs; agents w40 adds framework wrappers on top |
| Kubernetes operator, Helm, Gateway API | grantd w30; wicket w6, w50; toolgate w12, w45 | authz | w28 | HTTPRoutes attach forward-auth and MCP routing |
| CEL policy engine | grantd w3, toolgate w14 | authz | w4 | flow conditions, claims, conditional access and tool rules |
| What-if and policy simulation | grantd w37, toolgate w15 | authz | w37 | tool rule changes replayed against audit decisions |
| CLI and test file format | grantd w4, toolgate w1 (runner shipped, #24) | authz | w9 | tool policy cases run in the same format |
| Access reviews | grantd w36, wicket w47 | authz | w36 | app assignments and agent tool grants reviewed as relationships |
| Protobuf and gRPC framing | grantd w19, toolgate w28 | authz | w19 | agents w18 gRPC tools reuse it |
| Import framework | grantd w21, wicket w43 | authz | w21 | authn w31 user import runs on it |
| Local decision point and edge enforcement | grantd w41, wicket w51 | authz | w39 | authn w42 outposts embed it |
| Tenancy and organizations | grantd w8, wicket w15, toolgate w19 | authn | w7 (B2B self-service w38) | one tenant context scopes relationships, MCP policy and audit |
| Admin SSO and RBAC | grantd w27, wicket w32, toolgate w18 | authn | w16 | admin roles stored as relationships in the authz engine |
| Admin API and Terraform | wicket w33, toolgate w20 | authn | w18 | covers schemas, relationships, MCP servers and tool policy too |
| Admin console (TypeScript) | grantd w22; wicket w11, w34, w35; toolgate w21 | authn | w17 shell and people, w26 editors | domain pages ship with their feature on the shell: playground authz w26, approvals inbox agents w6, agent registry agents w16 |
| Key service, JOSE, sealed cookies | wicket w6, toolgate w3, grantd tokens | authn | w2 | consistency tokens, agent tokens and call assertions sign with it |
| OAuth authorization server and dynamic registration | wicket w18, w37; toolgate w16 | authn | w10, w15 | agents get identities and audience-bound tokens here |
| SCIM server | grantd w39, wicket w28 | authn | w24 | group memberships written as relationships |
| Handler fuzzing and hardening | grantd w47, wicket w10 | authn | w33 | covers sign-in, check and MCP handlers; authz w43 keeps fair scheduling |
| Authorization decision API | wicket w40 | dropped | n/a | the engine is the decision API: in process from authz w3, used by authn w4 and agents w5 |
| Audit log and tamper evidence | grantd w8, w29; wicket w4, w30; toolgate w2 | agents | w2, w3 | logins, admin actions, writes, decisions and tool calls in one Merkle chain |
| Event streaming and webhooks | grantd w40, wicket w30, toolgate w8 | agents | w9 | relationship change feed and identity events through one delivery system |
| Compliance exports and evidence | toolgate w47, wicket w47 (evidence) | agents | w33 | reports cover sign-in, access and agent activity |
| Observability (OpenTelemetry) | grantd w9, wicket w4, toolgate w9 | agents | w8 | one trace across forward-auth, check and tool call |
| Signed releases and supply chain | grantd w12, wicket w1 and w10, toolgate w11 | agents | w10 | one release workflow for the one binary |
| Rate limiting | wicket login limits, grantd w8, toolgate w4, w40 | agents | w2, fleet leases w45 | login, key and tool limits on one limiter |
| Approval engine | toolgate w5, w48; wicket w32 elevation | agents | w6, w31 | authn w16 elevation, w40 access requests and w50 admin consent use it |
| Usage metering | grantd w49, toolgate w22 | agents | w27 | hosted mode authz w49 bills on it |
| 1.0 release | grantd w52, wicket w12 and w52 (2.0), toolgate w52 | authz | w52 | one frozen surface for all three tracks |

## 2026-11 · One module and binary, shared platform, in-process checks, one audit chain and the benchmark gate

Due 2026-11-30. Weeks 1 to 5. The three repos become one Go module and one binary with one CI gate, with every old test passing unchanged; storage, metrics, HTTP server, keys, config, audit and logging are shared; the gateway and the MCP proxy get the in-process check API, the CEL engine and relationship-backed rules; one Merkle-provable audit chain covers every event; and the first published benchmark runs against seven competitors.

| Week | Dates | authn | authz | agents |
|---|---|---|---|---|
| 1 | Nov 2 to Nov 8 | Fold wicket in: internal/authn, the `authz gateway` subcommand and the wicket suite unchanged | One module and one binary: grantd at the root, the authz command with subcommands, one CI gate | Fold toolgate in: internal/agents, the `authz mcp` subcommand and the toolgate suite unchanged |
| 2 | Nov 9 to Nov 15 | Shared platform II: one key service, one sealed-cookie and JOSE library, one config schema with live reload | Shared platform I: one storage log, one metrics registry and one HTTP server for all three tracks | Shared platform III: one audit log, structured logging with correlation IDs and one rate limiter |
| 3 | Nov 16 to Nov 22 | Session lifecycle: revalidation, back-channel logout and SAML SLO | In-process checks for every track, plus expand, lookup subjects, delete by filter and schema dry run | One audit chain for the platform: rotation, signed checkpoints, Merkle proofs and query |
| 4 | Nov 23 to Nov 29 | Route rules backed by relationship checks, with step-up | One CEL engine for the platform: expiring relationships, caveats and conditional results | Agent token verification: JWKS, protected resource metadata and live keys |
| 5 | Nov 30 to Dec 6 | Protecting APIs: bearer tokens, introspection, DPoP and mTLS | Published benchmark and CI regression gate for checks, forward-auth and MCP calls against the leaders | Tool rules that ask the engine: relationship checks, conditions, time windows and budgets |

## 2026-12 · Disk store and replicas, tenants and users, approvals from relationships, platform observability

Due 2026-12-31. Weeks 6 to 9. A disk store and group commit under every track, read replicas, authz ctl with one test format; organizations and tenants across the platform, the user directory and account flows; approvals with approvers from relationships, resources and prompts, OpenTelemetry tracing and the event stream.

| Week | Dates | authn | authz | agents |
|---|---|---|---|---|
| 6 | Dec 7 to Dec 13 | Provider breadth and an interop matrix: private_key_jwt, PAR, multi-tenant issuers, metadata refresh | Disk store under every track: store interface, sorted segments, compaction | Approvals: approvers from relationships, two-person rule, signed notifications and durability |
| 7 | Dec 14 to Dec 20 | Organizations and tenants for the whole platform | Write path throughput: group commit, online checkpoints, idempotent retries, backpressure | Protocol coverage: resources, prompts, stdio upstreams and live list changes |
| 8 | Dec 21 to Dec 27 | User directory with password policy | Read replicas for the whole platform: replication stream, followers, token-aware reads, fenced promotion | Observability for the whole platform: OpenTelemetry tracing, stage metrics, upstream health and dashboards |
| 9 | Dec 28 to Jan 3 | Registration, verification and account recovery | authz ctl: one CLI and one test file format for schemas and tool policies, backup, restore and schema diff | Event stream for the platform: webhooks, SIEM shipping and the relationship change feed |

## 2027-01 · Go SDK, reverse lookups, Raft, the OpenID provider, passkeys, MFA and verifiable releases

Due 2027-01-31. Weeks 10 to 13. Go SDK and OpenAPI for every API, reverse lookups and a faster engine, the platform Raft library; authz as an OpenID Connect provider with conformance, passkeys and MFA; verifiable releases, the MCP hot path, the per-user credential vault and sampling under policy.

| Week | Dates | authn | authz | agents |
|---|---|---|---|---|
| 10 | Jan 4 to Jan 10 | OpenID Connect provider | Go SDK and OpenAPI for every API: checks, sign-in admin, MCP admin, middleware and watch consumer | Security assurance and verifiable releases for the one binary |
| 11 | Jan 11 to Jan 17 | Provider sessions, refresh rotation and OpenID conformance | Lookups at scale: reverse index, streamed lookups and shared sub-problems | MCP hot path performance: streaming decoder, zero-allocation allowed path and profile-guided builds |
| 12 | Jan 18 to Jan 24 | Passkeys and WebAuthn | Check engine performance: compiled plans, interning, materialized membership, cache admission | Per-user credential vault: upstream OAuth connections and token exchange |
| 13 | Jan 25 to Jan 31 | Multi-factor authentication | internal/platform/raft: a tested Raft implementation for the whole platform | Sampling, elicitation and roots under policy |

## 2027-02 · Replicated cluster, PostgreSQL, the flow engine, OAuth and identities for agents, admin RBAC and the console

Due 2027-02-28. Weeks 14 to 17. Every track's state on a Raft cluster with automatic failover, distributed dispatch, the materialized group index and PostgreSQL; the flow engine, OAuth for services and agents, admin RBAC modelled as relationships and the TypeScript console shell; long-running calls, virtual servers, agents as directory principals and REST APIs as tools.

| Week | Dates | authn | authz | agents |
|---|---|---|---|---|
| 14 | Feb 1 to Feb 7 | Authentication flow engine | Replicated cluster with automatic failover for relationships, sessions, directory and gateway state | Long-running calls: tasks, progress, cancellation and resumable streams |
| 15 | Feb 8 to Feb 14 | OAuth for services and agents: client credentials, token exchange, dynamic registration and MCP authorization | Distributed dispatch of check sub-problems | Virtual servers: aggregation, aliases and per-tool switches |
| 16 | Feb 15 to Feb 21 | Admin SSO and RBAC for the whole product, modelled as relationships | Materialized group membership index | Agent identities in the directory: owners, sponsors, lifecycle and delegated tokens |
| 17 | Feb 22 to Feb 28 | Admin console I (TypeScript): shell, admin sign-in, people, sessions and organizations | PostgreSQL datastore for every track over a hand-written wire protocol client | REST and OpenAPI to MCP |

## 2027-03 · Drop-in SpiceDB and OpenFGA APIs, SAML IdP, federation, the admin API, gRPC tools and guardrails

Due 2027-03-31. Weeks 18 to 22. MySQL and CockroachDB, SpiceDB and OpenFGA compatible APIs, relationship import with shadow mode and the language server; the admin API with Terraform, SAML IdP, brokering, LDAP and risk signals; gRPC and GraphQL tools, context optimisation, data-flow labels, content inspection and external guardrails.

| Week | Dates | authn | authz | agents |
|---|---|---|---|---|
| 18 | Mar 1 to Mar 7 | Complete admin API, declarative apply and a Terraform provider for every object | MySQL and CockroachDB datastores | gRPC and GraphQL to MCP |
| 19 | Mar 8 to Mar 14 | SAML identity provider | SpiceDB-compatible gRPC API | Context optimisation: tool search, lazy definitions and byte budgets |
| 20 | Mar 15 to Mar 21 | Identity brokering, social login and home realm discovery | OpenFGA-compatible HTTP API and DSL | Session data-flow labels and exfiltration rules |
| 21 | Mar 22 to Mar 28 | LDAP and Active Directory federation | Relationship import from SpiceDB and OpenFGA, and shadow mode | Content inspection: personal data, secrets and hidden instructions |
| 22 | Mar 29 to Apr 4 | Risk signals, bot defence and device posture | Language server, editor extension and the first quarterly re-benchmark | External guardrails and definition risk analysis |

## 2027-04 · TypeScript, Python and Java SDKs, attributes, SCIM and lifecycle, sandboxes and the server registry

Due 2027-04-30. Weeks 23 to 26. TypeScript, Python and Java SDKs, attribute policies and the playground; claims mapping, SCIM feeding relationships, outbound provisioning and console editors; signed call assertions, the Linux sandbox, the container runner and the registry.

| Week | Dates | authn | authz | agents |
|---|---|---|---|---|
| 23 | Apr 5 to Apr 11 | Claims mapping, header mutators and login actions | TypeScript SDK: checks, identity administration, MCP administration and browser sign-in helpers | Gateway-signed call assertions |
| 24 | Apr 12 to Apr 18 | SCIM 2.0 server feeding the directory and group relationships | Python and Java SDKs from the shared OpenAPI description | Linux sandbox for local servers: namespaces, seccomp and Landlock |
| 25 | Apr 19 to Apr 25 | Outbound provisioning and lifecycle workflows | Attribute policies over relationships | Container runner for MCP servers |
| 26 | Apr 26 to May 2 | Admin console II: applications, providers, flows, branding and localization | Schema playground and access-sharing widgets | Server registry and catalog with hash pinning |

## 2027-05 · Encryption, Kubernetes, multi-region, backups, FAPI, user import and retrieval authorization

Due 2027-05-31. Weeks 27 to 31. Encryption at rest with tenant keys, the operator and Gateway API, multi-region reads, platform backups and range sharding; custom domains, device grant and CIBA, FAPI 2.0, identity hot path performance and user import; metering, retrieval authorization, desktop mode, agent-to-agent and approval delivery.

| Week | Dates | authn | authz | agents |
|---|---|---|---|---|
| 27 | May 3 to May 9 | Custom domains, certificates and branded email | Encryption at rest and in transit for every track, crypto-shredding keys and a FIPS build | Usage analytics, metering, quotas and cost reporting for the platform |
| 28 | May 10 to May 16 | Device grant, native apps and back-channel authentication | Kubernetes operator, Helm chart and Gateway API integration | Retrieval authorization for agents: filter retrieved documents by relationships |
| 29 | May 17 to May 23 | FAPI 2.0 security profile and conformance | Multi-region reads, region failover and a failover drill | Desktop mode: authz as a local front end |
| 30 | May 24 to May 30 | Forward-auth and token path performance: zero allocations, group commit on logins, sharded sessions | Backups, point-in-time restore and disaster recovery for the whole platform | Agent-to-agent gateway |
| 31 | May 31 to Jun 6 | User import from Keycloak, Auth0, Okta and others with password hashes | Multi-Raft range sharding | Approval delivery: chat actions, email, escalation, standing grants and CIBA |

## 2027-06 · A billion relationships, device-bound sessions, Shared Signals, Cross App Access and model traffic

Due 2027-06-30. Weeks 32 to 35. Cross-shard transactions, placement, the billion-relationship benchmark and streamed lookups; device-bound sessions, handler hardening, Shared Signals and the account portal; Cross App Access, compliance exports, upstream traffic management and LLM routing with budgets.

| Week | Dates | authn | authz | agents |
|---|---|---|---|---|
| 32 | Jun 7 to Jun 13 | Device-bound sessions | Cross-shard transactions with hybrid-clock tokens | Cross App Access: identity assertion grants for agents reaching other apps |
| 33 | Jun 14 to Jun 20 | Hardening every handler: structured fuzzing across sign-in, checks and MCP, smuggling defences and a weekly soak | Placement and rebalancing | Compliance exports and evidence reports |
| 34 | Jun 21 to Jun 27 | Shared Signals: CAEP and RISC transmitter and receiver | Cross-shard dispatch, a billion-relationship benchmark and the second quarterly re-benchmark | Traffic management for upstreams: retries, circuit breaking, response caching and load balancing |
| 35 | Jun 28 to Jul 4 | Self-service account portal: profile, passkeys and factors, sessions, connected apps and agents | Lookups streamed over shards | Model traffic: LLM provider routing, token budgets and model guardrails |

## 2027-07 · Access reviews, what-if, conditional access, workload identity, anomaly detection and the kill switch

Due 2027-07-31. Weeks 36 to 39. Access reviews, what-if and shadow rules, time travel and the local decision point; conditional access, workload identity federation, B2B self-service and consent records; agent baselines with quarantine, MCP conformance, the kill switch and policy packs.

| Week | Dates | authn | authz | agents |
|---|---|---|---|---|
| 36 | Jul 5 to Jul 11 | Conditional access policies across sign-in, apps and agents | Access reviews and who-has-access reports across apps, relationships and agents | Agent behaviour baselines, anomaly detection and automatic quarantine |
| 37 | Jul 12 to Jul 18 | Workload identity federation: Kubernetes, CI and cloud workload tokens exchanged for authz tokens | What-if, shadow rules and replay for schemas and tool policies | MCP conformance suite and client interop matrix |
| 38 | Jul 19 to Jul 25 | B2B self-service: organization admin portal, invitations, and SSO and SCIM setup wizards | Time-travel queries over retained history | Kill switch and incident response for agents |
| 39 | Jul 26 to Aug 1 | Terms, privacy consent records and progressive profiling for customer identity | Local decision point for low-latency checks | Policy packs for common MCP servers with tests |

## 2027-08 · Upgrades, simulation, footprint, edge outposts, verifiable credentials, delegation chains and code mode

Due 2027-08-31. Weeks 40 to 44. Rolling upgrades, deterministic simulation, footprint round two, fair scheduling and data residency; access requests, LDAP and RADIUS front-ends, edge outposts, Kerberos and verifiable credentials; framework integrations, delegation chains, human presence for sensitive tools, the control plane split and code mode.

| Week | Dates | authn | authz | agents |
|---|---|---|---|---|
| 40 | Aug 2 to Aug 8 | Access requests: self-service app and resource access with expiring grants | Rolling upgrades and on-disk format versioning for every track | Agent framework integrations: in-process Go library and middleware for TypeScript and Python agents |
| 41 | Aug 9 to Aug 15 | LDAP and RADIUS front-ends for legacy applications | Deterministic simulation of the cluster | Delegation chains: down-scoped tokens across agent hops |
| 42 | Aug 16 to Aug 22 | Edge outposts for forward-auth near apps | Footprint round two: memory and cold start for the one binary | Human presence for sensitive tool calls: passkey confirmation per tool |
| 43 | Aug 23 to Aug 29 | Integrated Windows sign-in with Kerberos and SPNEGO | Fair scheduling between workloads, expensive-query throttling and the threat model | Control plane and data plane split for remote gateways with signed policy bundles |
| 44 | Aug 30 to Sep 5 | Verifiable credentials: OpenID4VCI issuance and OpenID4VP presentation | Data residency, retention and subject erasure across tracks, and the third quarterly re-benchmark | Code mode: tools as a typed API run in a sandbox |

## 2027-09 · Data filtering, policy import, authenticator policy, push MFA, threat detection and fleet limits

Due 2027-09-30. Weeks 45 to 48. Permission-aware SQL and search filters, Cedar and Rego import, mesh external authorization and .NET and Ruby SDKs; authenticator policy, the app catalog, push MFA and identity threat detection; fleet-wide limits, MCP server auth middleware, reputation feeds and session recording.

| Week | Dates | authn | authz | agents |
|---|---|---|---|---|
| 45 | Sep 6 to Sep 12 | Authenticator policy: FIDO metadata, attestation enforcement and assurance levels | Data filtering: compile permissions into SQL and search filters | Fleet-wide rate limits and budgets with leases on the cluster |
| 46 | Sep 13 to Sep 19 | Application catalog: 40 preconfigured SaaS integrations with SAML, OIDC and SCIM templates | Cedar and Rego policy import into schemas and attribute rules | Authorization for MCP server authors: middleware that offloads auth to authz |
| 47 | Sep 20 to Sep 26 | Push MFA with a reference authenticator as an installable web app | Service mesh external authorization: Envoy ext_authz, Istio and Kubernetes admission | Server and package reputation: vulnerability matching and known-bad feeds |
| 48 | Sep 27 to Oct 3 | Identity threat detection and automatic response | .NET and Ruby SDKs and a shared SDK conformance suite | Session recording and forensic replay with redaction |

## 2027-10 · Hosted mode, conformance, sign-in components, SSH certificates, agent spend controls and authz 1.0

Due 2027-10-31. Weeks 49 to 52. Hosted mode, SpiceDB and OpenFGA conformance, schema modules and authz 1.0 with the final benchmark; sign-in components, grant management, short-lived SSH and Kubernetes access and OpenID Federation; spend mandates, least-privilege recommendations, honeytokens and browser tool controls.

| Week | Dates | authn | authz | agents |
|---|---|---|---|---|
| 49 | Oct 4 to Oct 10 | Sign-in, sign-up and MFA enrollment web components | Hosted service mode: self-serve signup, dedicated shards and SLO reports | Spend controls for agents that buy things: mandates, thresholds and approvals |
| 50 | Oct 11 to Oct 17 | Third-party app consent and grant management | Conformance against SpiceDB and OpenFGA client suites | Least-privilege recommendations for agents |
| 51 | Oct 18 to Oct 24 | Short-lived certificates for SSH and Kubernetes access | Schema modules, imports and versioned schemas | Honeytokens and decoy tools to catch prompt injection and exfiltration |
| 52 | Oct 25 to Oct 31 | OpenID Federation trust chains for multi-issuer deployments | authz 1.0: frozen APIs and formats, final benchmark and a reference deployment | Browser and computer-use tool controls |

## Next year

- Spanner as a datastore.
- SOC 2 Type II, ISO 27001 or FedRAMP attestations for hosted mode, which are organisational rather than code work.
- Native iOS and Android authenticator apps for push MFA beyond the web app authenticator.
- An application catalog in the thousands rather than 40 templates.
- Browser-based remote access to RDP, SSH and VNC sessions.
- PHP and Rust SDKs, and a packaged JetBrains plugin for the schema language.
- Full Rego coverage beyond the documented subset.
- HSM-native signing through PKCS#11.
- Identity proofing with document verification.
- A multi-operator managed control plane beyond single-operator hosted mode.
