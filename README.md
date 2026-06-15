# TriagaSOAR

Most SOAR platforms are expensive, opaque, and built for enterprises that already have a full security team. TriagaSOAR is different. It is an open, agentic SOAR platform that combines Splunk alert ingestion, local LLM-powered investigation, cross-platform identity correlation, automated playbook execution, and cryptographically gated response actions into a single deployable stack. You bring your Splunk instance and your IDPs. TriagaSOAR does the rest.

Built for the [Splunk Agentic Ops Hackathon 2026](https://splunk.devpost.com/) — Security track + Best Use of Splunk MCP Server.

---

## What it does

### Splunk-native investigation

TriagaSOAR uses the Splunk MCP Server as the exclusive interface between its AI agents and Splunk data. No direct SDK calls. No hardcoded queries. Everything goes through MCP tool calls, and every query is generated autonomously by the LLM based on what it finds at each investigation step.

When an alert arrives (via webhook or manual submission), the investigation pipeline runs:

1. A router agent (Qwen3 1.7B) classifies the alert type and selects an initial SPL query
2. A primary agent (Qwen3 14B) runs a multi-step pivot loop: it executes SPL via MCP, reads the results, scores the finding, and derives the next query from what it found
3. An adversarial agent (Qwen3 14B) critiques the findings and issues a verdict
4. The final report assembles: MITRE ATT&CK technique mapping, blast radius, AbuseIPDB threat intelligence enrichment, confidence score, kill chain summary, and remediation recommendations

Reports export as PDF or MITRE Navigator JSON layers.

**Splunk deployment options:**
- **Containerized** — self-contained Splunk + MCP Server in Docker, pre-seeded with synthetic attack data. Zero setup. `make up-splunk` and you are running.
- **External** — your existing Splunk Enterprise instance (KVM, bare metal, cloud). Configure once and point TriagaSOAR at it.

Switch between them at runtime with `make use-splunk-container` or `make use-splunk-external`.

### YAML playbook engine

After every investigation, TriagaSOAR evaluates all loaded playbooks against the completed report. Playbooks are YAML files in `soc-agent/playbooks/` and support:

- **Conditions:** `confidence_gte`, `severity_in`, `techniques_include`, `tactics_include`, `repeated_attacker`
- **Actions:** `entra_revoke_sessions`, `entra_disable_user`, `okta_suspend`, `okta_clear_sessions`, `auth0_block`, `splunk_saved_search`, `webhook`, `teams`
- **Template variables:** `{{affected_user}}`, `{{attacker_ip}}`, `{{confidence}}`, `{{technique_ids}}`

Four starter playbooks ship with the repo covering credential stuffing, brute force lockout, repeated attacker escalation, and high-severity notification.

### Velociraptor endpoint hunting

When an investigation identifies suspicious hosts, TriagaSOAR automatically dispatches Velociraptor artifact collections against them. Artifacts are selected based on alert type: brute force, lateral movement, credential stuffing, and privilege escalation each get a different artifact set. Results are included in the investigation report.

Velociraptor runs as an optional Docker container on the `velociraptor` profile. The GUI is available at `https://localhost:8889`.

### Cross-platform identity correlation

When an alert involves a user, TriagaSOAR looks that user up across all three configured IDPs simultaneously and joins the results into a unified risk assessment, flagging cases where the same suspicious IP appears in multiple providers.

### M365 security posture

Two optional containers surface Microsoft 365 compliance results: **Maester** (automated security tests) and **ScubaGear** (CISA SCuBA baseline checks, Linux-patched to run in Docker).

### Single-Action Tokens

Every destructive response action requires a Single-Action Token. 32-byte random token, Argon2id-hashed at rest, 60-second TTL, single-use, requires a written reason. Every step is written to the tamper-evident audit log.

### Auth layer

A Rust/Axum auth proxy sits in front of everything. Argon2id session hashing, IP and user-agent binding, hash-chained audit log in a separate Postgres schema with an INSERT-only role. Admin credentials loaded from Docker secrets, never in environment variables or visible via `docker inspect`.

---

## Stack

| Layer | Technology |
|-------|-----------|
| Auth proxy | Rust / Axum |
| Session store | Postgres 16 |
| SOC agent | Python / FastAPI |
| Local LLM | Ollama / Qwen3:14b + Qwen3:1.7b |
| Frontend | Astro + React |
| Backend | Rust / Axum |
| Splunk integration | Splunk MCP Server |
| DFIR | Velociraptor |
| Entra ID | Microsoft Graph API |
| Okta | Okta Management API |
| Auth0 | Auth0 Management API |
| M365 baseline | Maester, ScubaGear (Linux-patched) |
| Case persistence | SQLite |
| Threat intel | AbuseIPDB |

---

## Prerequisites

**Hardware (local LLM mode)**
- NVIDIA GPU with 16GB+ VRAM (Qwen3 14B requires ~9GB at Q4)
- 16GB+ system RAM

**Software**
- Docker + Docker Compose
- nvidia-container-toolkit (local mode only)

**Splunk (external mode only — containerized mode has no prerequisites)**
- Splunk Enterprise 10.x with MCP Server installed
- Token authentication enabled, `mcp_user` role with `mcp_tool_execute` capability
- Encrypted MCP token generated from the MCP Server app

---

## Quick start

### 1. Clone

```bash
git clone https://github.com/TriagaSOAR/TriagaSOAR
cd TriagaSOAR
```

### 2. Run the setup wizard

```bash
bash scripts/setup.sh
```

The wizard walks through LLM mode, Splunk mode, database credentials, identity provider connections, Velociraptor, threat intelligence, and Teams notifications. It writes `.env` and generates `secrets/` automatically.

### 3. Start the main stack

```bash
# Local GPU mode (requires NVIDIA GPU, pulls Qwen3 14B + 1.7B automatically)
make up

# Cloud LLM mode (OpenAI or Anthropic, set keys in .env)
make up-cloud
```

### 4a. Containerized Splunk (zero setup, recommended for evaluation)

```bash
make up-splunk
```

This starts Splunk Enterprise, waits for healthy (3-5 min), generates the MCP token, configures roles, and seeds three synthetic attack scenarios. No Splunk license required.

Once complete, TriagaSOAR is fully connected. Open `http://localhost:4321` and log in.

### 4b. External Splunk (your existing instance)

If you already have Splunk Enterprise running, configure it first:

1. Install the [Splunk MCP Server](https://splunkbase.splunk.com/app/7931) (app ID 7931)
2. Enable token authentication: Settings > Tokens > Enable
3. Create a role named exactly `mcp_user`: Settings > Access Controls > Roles > New Role
4. Assign the `mcp_tool_execute` capability to `mcp_user`
5. Assign `mcp_user` to your Splunk user
6. Open the MCP Server app and generate a new encrypted token with Audience set to `mcp`
7. Set these values in `.env`:

```env
SPLUNK_HOST=your-splunk-host
SPLUNK_PORT=8089
SPLUNK_TOKEN=your-encrypted-mcp-token
SPLUNK_TOKEN_FILE=
SPLUNK_VERIFY_SSL=false
```

8. Restart soc-agent to pick up the new token:

```bash
docker restart soc-agent
```

9. Verify the connection:

```bash
curl -s http://localhost:8000/splunk/health | python3 -m json.tool
```

You should see your Splunk version and index list.

**Switching between containerized and external Splunk at runtime (no rebuild needed):**

```bash
# Switch to containerized Splunk
make use-splunk-container

# Switch to external Splunk (prompts for token)
make use-splunk-external
```

### 5. Velociraptor (optional)

```bash
make up-velociraptor
make velociraptor-setup
```

The GUI is available at `https://localhost:8889`. Log in with the credentials you set for `VELOX_USER` and `VELOX_PASSWORD` in `.env`.

### 6. Run a demo investigation

```bash
make demo
```

This resets the case database and triggers investigations against all three synthetic attack scenarios: brute force, credential stuffing, and lateral movement.

---

## Makefile

| Command | Description |
|---------|-------------|
| `make setup` | Interactive setup wizard |
| `make up` | Start all services (local GPU) |
| `make up-cloud` | Start all services (cloud LLM) |
| `make up-splunk` | Start containerized Splunk + seed data |
| `make up-velociraptor` | Start Velociraptor container |
| `make down` | Stop everything |
| `make rebuild` | Rebuild and restart (local) |
| `make rebuild-cloud` | Rebuild and restart (cloud) |
| `make splunk-setup` | Re-run Splunk setup (token + seed) |
| `make splunk-token` | Print current MCP token |
| `make velociraptor-setup` | Generate Velociraptor API config + admin user |
| `make use-splunk-container` | Switch to containerized Splunk at runtime |
| `make use-splunk-external` | Switch to external Splunk at runtime |
| `make pull-models` | Pull Ollama models |
| `make logs` | Tail soc-agent logs |
| `make demo` | Full demo run (reset DB + investigations) |
| `make reset-db` | Wipe case database |
| `make attack` | Run attack simulation |
| `make query Q="..."` | Run a raw Splunk query |

---

## Project structure

```
├── auth/                       # Rust/Axum auth proxy + SAT system
├── soc-agent/                  # Python investigation agent
│   ├── main.py                 # FastAPI app, all routes
│   ├── agent.py                # Router + primary + adversarial agents
│   ├── splunk_mcp.py           # Splunk MCP client (env + file token)
│   ├── velociraptor.py         # Velociraptor hunt integration
│   ├── playbooks.py            # YAML playbook engine
│   ├── playbooks/              # Starter playbooks
│   ├── blast_radius.py         # Blast radius estimation
│   ├── report.py               # IR report generator
│   ├── database.py             # SQLite case persistence
│   ├── patterns.py             # Attack pattern library
│   ├── threat_intel.py         # AbuseIPDB enrichment
│   ├── entra.py                # Microsoft Graph API client
│   ├── okta.py                 # Okta Management API client
│   └── auth0.py                # Auth0 Management API client
├── web-backend/                # Rust/Axum transparent proxy
├── web-frontend/               # Astro + React dashboard
├── postgres/                   # Postgres init scripts
├── integrations/
│   ├── splunk/                 # Containerized Splunk + MCP Server
│   │   ├── Dockerfile
│   │   ├── scripts/setup.sh    # MCP token generation + role config
│   │   ├── scripts/seed.sh     # Synthetic attack data seeding
│   │   └── sample-data/        # auth.log + attack.log
│   ├── velociraptor/           # Velociraptor API setup script
│   ├── maester/                # PowerShell + Maester container
│   └── scubagear/              # PowerShell + ScubaGear (Linux-patched)
├── scripts/
│   ├── setup.sh                # Interactive setup wizard
│   ├── demo.sh                 # Demo investigation runner
│   ├── attack-simulation.sh
│   ├── reset-db.sh
│   ├── splunk-query.sh
│   └── test-webhook.sh
├── secrets/                    # Docker secrets (gitignored)
│   ├── admin_password.txt
│   └── session_secret.txt
├── docker-compose.yml
├── Makefile
├── .env.example
└── Architecture.md
```

---

## Profiles

| Profile | Services |
|---------|---------|
| `local` | ollama, soc-agent, web-backend, web-frontend, auth, postgres |
| `cloud` | soc-agent (cloud), web-backend, web-frontend, auth, postgres |
| `splunk` | Splunk Enterprise + MCP Server (additive) |
| `velociraptor` | Velociraptor DFIR platform (additive) |
| `maester` | Maester M365 checks (additive) |
| `scubagear` | ScubaGear CISA baseline (additive) |

---

## Synthetic attack data

The containerized Splunk ships pre-seeded with three attack scenarios:

| Scenario | Source IP | Description |
|----------|-----------|-------------|
| Brute force | 185.220.101.47 | 50+ failed SSH attempts, successful login as `dave`, privilege escalation |
| Credential stuffing | 45.33.32.156 | 9 accounts attempted, 2 successful (alice, carol) |
| Lateral movement | 10.0.1.99 | Internal pivot as `svc-deploy`, implant download, root SSH |

Run `make demo` to trigger investigations against all three.

---

## Architecture

See [Architecture.md](Architecture.md) for Mermaid diagrams covering the container topology, auth sequence, SAT flow, investigation pipeline, identity correlation, and playbook engine.

---

## License

MIT
