# Architecture — TriagaSOAR

---

## System topology

```mermaid
graph TD
    Browser --> auth

    subgraph auth["auth — Rust/Axum :4000"]
        A1[Session validation]
        A2[Single-Action Tokens]
        A3[Audit log writer]
        A4[Reverse proxy]
        A5[User management]
    end

    auth --> frontend
    auth --> backend
    auth --> postgres

    subgraph frontend["web-frontend — Astro+React :4321"]
        F1[Login / SAT modal]
        F2[Investigation UI + SSE]
        F3[Identity panels]
        F4[Playbooks UI]
        F5[Velociraptor UI]
        F6[Settings / user management]
    end

    subgraph backend["web-backend — Rust/Axum :3000"]
        B1[Transparent proxy to soc-agent]
    end

    backend --> agent

    subgraph agent["soc-agent — Python/FastAPI :8000"]
        AG1[Agentic investigation pipeline]
        AG2[Identity correlation engine]
        AG3[NL to SPL — sanitized]
        AG4[Blast radius estimation]
        AG5[MITRE ATT&CK mapping]
        AG6[YAML playbook engine]
        AG7[Velociraptor hunt dispatcher]
        AG8[PDF + Navigator export]
    end

    agent --> ollama
    agent --> splunk_c
    agent --> splunk_e
    agent --> sqlite
    agent --> velo

    subgraph ollama["ollama :11434 — local profile"]
        O1[qwen3:14b — primary + adversarial]
        O2[qwen3:1.7b — router]
    end

    subgraph splunk_c["integrations/splunk — splunk profile"]
        SC1[Splunk Enterprise 10.2]
        SC2[MCP Server app]
        SC3[Synthetic attack data]
        SC4[Token auto-generated on boot]
    end

    subgraph splunk_e["External Splunk — optional"]
        SE1[Existing Splunk instance]
        SE2[MCP Server installed]
    end

    subgraph velo["velociraptor :8889/:8001/:8002 — velociraptor profile"]
        V1[Velociraptor server]
        V2[gRPC API :8001]
        V3[GUI :8889]
        V4[Client frontend :8002]
    end

    sqlite[(SQLite — cases.db)]
    postgres[(Postgres :5432)]

    subgraph postgres_schemas["Postgres schemas"]
        P1[public — sessions, users, action_tokens]
        P2[audit — hash-chained, INSERT-only]
    end

    postgres --- postgres_schemas

    agent --> entra["Microsoft Graph API"]
    agent --> okta_api["Okta Management API"]
    agent --> auth0_api["Auth0 Management API"]
    agent --> abuseipdb["AbuseIPDB"]
    agent --> teams["Teams webhook"]

    maester["maester — maester profile"] --> maester_vol[(./data/maester)]
    scubagear["scubagear — scubagear profile"] --> scubagear_vol[(./data/scubagear)]
    agent --> maester_vol
    agent --> scubagear_vol

    secrets["secrets/ — Docker secrets"]
    secrets --> auth
```

---

## Auth sequence

```mermaid
sequenceDiagram
    participant Browser
    participant auth as auth :4000
    participant Postgres

    Browser->>auth: POST /auth/login {username, password, totp}
    auth->>Postgres: verify argon2id hash
    Postgres-->>auth: user record
    auth->>Postgres: create session (token hash, IP, UA, expires)
    auth-->>Browser: Set-Cookie: soc_session (HttpOnly, SameSite=Strict)

    Browser->>auth: GET /entra/risky-users + cookie
    auth->>Postgres: validate session token hash + IP + UA
    Postgres-->>auth: session valid
    auth->>auth: proxy request to soc-agent
    auth-->>Browser: response
```

---

## Single-Action Token flow

```mermaid
sequenceDiagram
    participant Analyst
    participant Frontend
    participant auth as auth :4000
    participant Postgres
    participant IDP

    Analyst->>Frontend: click response action
    Frontend->>Analyst: SAT modal — enter reason (min 20 chars)
    Analyst->>Frontend: submit reason

    Frontend->>auth: POST /api/sat/issue {action, target, reason}
    auth->>Postgres: store token hash, 60s TTL
    auth-->>Frontend: raw token + expires_in_seconds

    Frontend->>Analyst: confirmation screen — action / target / reason
    Analyst->>Frontend: Confirm & Execute

    Frontend->>auth: POST /api/sat/consume {token, action, target}
    auth->>Postgres: validate hash, mark consumed
    Postgres-->>auth: valid
    auth->>IDP: execute action
    IDP-->>auth: success
    auth->>Postgres: write audit record (hash-chained)
    auth-->>Frontend: success
```

---

## Investigation pipeline

```mermaid
flowchart TD
    A[Alert — webhook or manual] --> B[correlate — check prior cases]
    B --> C[router_agent — Qwen3 1.7B]
    C --> D[classifies alert type, selects initial SPL]
    D --> E[primary_agent loop — Qwen3 14B]
    E --> F[run SPL via Splunk MCP]
    F --> G[parse results, score finding]
    G --> H{new pivot?}
    H -- yes --> E
    H -- no --> I[adversarial_agent — Qwen3 14B]
    I --> J{verdict}
    J -- challenged --> E
    J -- approved --> K[generate_ir_report]
    K --> L[estimate_blast_radius]
    K --> M[enrich_ips via AbuseIPDB]
    K --> N[map MITRE ATT&CK]
    L & M & N --> O[Velociraptor hunt affected hosts]
    O --> P[save_report to SQLite]
    P --> Q[run_playbooks — YAML engine]
    Q --> R[stream findings via SSE]
```

---

## Playbook engine

```mermaid
flowchart LR
    R[Completed report] --> PE[Playbook engine]
    PE --> C1{confidence_gte?}
    PE --> C2{severity_in?}
    PE --> C3{techniques_include?}
    PE --> C4{repeated_attacker?}
    C1 & C2 & C3 & C4 --> MATCH{All conditions met?}
    MATCH -- yes --> ACTIONS
    subgraph ACTIONS["Actions"]
        A1[entra_revoke_sessions]
        A2[okta_suspend]
        A3[auth0_block]
        A4[splunk_saved_search]
        A5[teams notification]
        A6[webhook]
    end
    ACTIONS --> DB[(playbook_executions SQLite)]
```

---

## Identity correlation

```mermaid
flowchart LR
    Q["GET /identity/correlate?email=user@example.com"]
    Q --> E[Entra ID\nrisk level, state, sign-in failures]
    Q --> O[Okta\nstatus, failed logins, recent IPs]
    Q --> A[Auth0\nblocked, failed logins, recent IPs]
    E & O & A --> R[aggregate risk signals]
    R --> S[flag shared IPs across IDPs]
    S --> T[unified risk assessment]
```

---

## Containerized Splunk boot sequence

```mermaid
sequenceDiagram
    participant Docker
    participant Splunk
    participant setup.sh
    participant soc-agent

    Docker->>Splunk: start container (splunk profile)
    Splunk->>Splunk: Ansible provisioning (~3-5 min)
    Splunk-->>Docker: healthy

    Docker->>setup.sh: make splunk-setup
    setup.sh->>Splunk: create mcp_user role
    setup.sh->>Splunk: enable token auth
    setup.sh->>Splunk: clean ghost credentials
    setup.sh->>Splunk: restart splunkd
    setup.sh->>Splunk: GET /services/mcp_token?username=admin&expires_on=+180d
    Splunk-->>setup.sh: encrypted MCP token
    setup.sh->>setup.sh: write token to /shared/splunk_token

    Docker->>setup.sh: seed.sh
    setup.sh->>Splunk: splunk add oneshot auth.log
    setup.sh->>Splunk: splunk add oneshot attack.log

    soc-agent->>soc-agent: read SPLUNK_TOKEN_FILE=/splunk-shared/splunk_token
    soc-agent->>Splunk: MCP tool calls via bearer token
```

---

## Container details

### auth (port 4000)

- **Stack:** Rust, Axum, sqlx, argon2, totp-rs, sha2
- **Secrets:** `ADMIN_PASSWORD` and `SESSION_SECRET` loaded from Docker secrets (`/run/secrets/`), never in environment variables

**Session properties**
- 32-byte CSPRNG tokens, Argon2id-hashed at rest
- HttpOnly, SameSite=Strict cookies, 30-minute absolute expiry
- IP address + user agent binding
- One concurrent session per user

**User management endpoints**
- `GET /users` — list all users (admin only)
- `POST /users` — create user (admin only, defaults to `analyst` role)
- `DELETE /users/{id}` — deactivate user (admin only, cannot deactivate self)
- `POST /users/change-password` — any authenticated user

**Audit log**
- Separate `audit` Postgres schema, INSERT-only role
- SHA-256 hash-chained entries
- Chain integrity verifiable via `GET /audit/verify`

---

### soc-agent (port 8000)

**Key modules**

| File | Responsibility |
|------|---------------|
| `main.py` | FastAPI app, all routes |
| `agent.py` | Router + primary + adversarial agents |
| `splunk_mcp.py` | MCP client — reads token from file or env var |
| `velociraptor.py` | Hunt dispatcher via docker exec |
| `playbooks.py` | YAML playbook engine |
| `blast_radius.py` | Affected IPs, users, hosts |
| `report.py` | Structured IR report assembly |
| `database.py` | SQLite: cases, entities, verdicts, playbook executions |
| `patterns.py` | 21 attack patterns + 9 EDR evasion hunts |
| `threat_intel.py` | AbuseIPDB lookups with cache |
| `entra.py` | Microsoft Graph API client |
| `okta.py` | Okta Management API client |
| `auth0.py` | Auth0 Management API client |

**NL to SPL security**
- User input isolated in separate LLM message
- Injection pattern blocklist on input
- SPL validator on output: index check, dangerous command ban, 1000-char cap

---

### integrations/splunk

- Base: `splunk/splunk:10.2` official image
- Web UI disabled (`startwebserver = false`) to avoid port 8000 conflict
- MCP Server pre-baked at build time
- Token auto-generated on first `make splunk-setup`
- Ghost credential cleanup baked into `setup.sh` (upstream bug in `crypto.py` — `allow_overwrite=True` not used on first key generation)
- Token written to shared Docker volume, read by soc-agent via `SPLUNK_TOKEN_FILE`

---

### velociraptor (ports 8889/8001/8002)

- Image: `xboarder56/velociraptor:latest`
- API config generated via `make velociraptor-setup` (`config api_client --name localhost --role administrator`)
- soc-agent calls Velociraptor via `docker exec` (bypasses gRPC TLS hostname verification issue)
- API config written to shared volume, mounted read-only in soc-agent
- Hunt dispatch and artifact collection triggered automatically after each investigation

---

## Ports

| Service | Port | Notes |
|---------|------|-------|
| auth | 4000 | Single entry point for all traffic |
| web-frontend | 4321 | Via auth proxy |
| web-backend | 3000 | Via auth proxy |
| soc-agent | 8000 | Via auth proxy |
| ollama | 11434 | Via auth proxy |
| postgres | 5432 | Internal only |
| Splunk management | 8089 | Splunk profile only |
| Velociraptor GUI | 8889 | Velociraptor profile only |
| Velociraptor gRPC | 8001 | Velociraptor profile only |
| Velociraptor clients | 8002 | Velociraptor profile only |

---

## Profiles

| Profile | Services |
|---------|---------|
| `local` | ollama, soc-agent-local, web-backend, web-frontend, auth, postgres |
| `cloud` | soc-agent-cloud, web-backend, web-frontend, auth, postgres |
| `splunk` | Splunk Enterprise + MCP Server (additive) |
| `velociraptor` | Velociraptor DFIR platform (additive) |
| `maester` | Maester M365 checks (additive) |
| `scubagear` | ScubaGear CISA baseline (additive) |

---

## Storage

| Store | Location | Contents |
|-------|----------|---------|
| SQLite | `./data/cases.db` | Cases, entities, verdicts, playbook executions, threat intel cache |
| Postgres | Docker volume `postgres_data` | Sessions, users, action tokens, audit log |
| Ollama models | Docker volume `ollama_data` | Model weights |
| Splunk data | Docker volume `splunk_data` | Splunk indexes and config |
| Shared token | Docker volume `splunk_shared` | MCP token file |
| Velociraptor data | Docker volume `velociraptor_data` | Server config, client enrollments |
| Velociraptor API | Docker volume `velociraptor_shared` | API config for soc-agent |
| Secrets | `./secrets/` | admin_password.txt, session_secret.txt (gitignored) |