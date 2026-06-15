#!/bin/bash
# scripts/setup.sh -- TriagaSOAR interactive setup wizard
# Generates .env and secrets/ from user input

set -e

BOLD='\033[1m'
DIM='\033[2m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

ENV_FILE=".env"

print_header() {
    echo ""
    echo -e "${CYAN}${BOLD}TriagaSOAR Setup${NC}"
    echo -e "${DIM}-----------------------------------------${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${BOLD}$1${NC}"
    echo -e "${DIM}-----------------------------------------${NC}"
}

ask() {
    local prompt="$1" default="$2" var
    if [ -n "$default" ]; then
        read -p "$(echo -e "${CYAN}?${NC} $prompt [${DIM}$default${NC}]: ")" var
        echo "${var:-$default}"
    else
        read -p "$(echo -e "${CYAN}?${NC} $prompt: ")" var
        echo "$var"
    fi
}

ask_yn() {
    local prompt="$1" default="${2:-n}" var
    read -p "$(echo -e "${CYAN}?${NC} $prompt [y/N]: ")" var
    var="${var:-$default}"
    [[ "$var" =~ ^[Yy]$ ]]
}

ask_secret() {
    local prompt="$1" var
    read -s -p "$(echo -e "${CYAN}?${NC} $prompt: ")" var
    echo ""
    echo "$var"
}

write_env() {
    local key="$1" val="$2"
    if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
        sed -i "s|^${key}=.*|${key}=${val}|" "$ENV_FILE"
    else
        echo "${key}=${val}" >> "$ENV_FILE"
    fi
}

gen_password() {
    openssl rand -hex 24 2>/dev/null || cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32
}

print_header

if [ ! -f "$ENV_FILE" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example "$ENV_FILE"
        echo -e "${GREEN}Created .env from .env.example${NC}"
    else
        touch "$ENV_FILE"
    fi
fi

# LLM Mode
print_section "LLM Mode"
echo -e "  ${BOLD}0${NC}  Local  (Ollama, Qwen3 14B + 1.7B, requires ~15-20GB VRAM)"
echo -e "  ${BOLD}1${NC}  Cloud  (OpenAI or Anthropic, requires API key)"
LLM_CHOICE=$(ask "Select LLM mode" "0")

if [ "$LLM_CHOICE" = "1" ]; then
    write_env "LLM_MODE" "cloud"
    echo -e "  ${BOLD}0${NC}  OpenAI    ${BOLD}1${NC}  Anthropic"
    PROVIDER_CHOICE=$(ask "Select provider" "1")
    if [ "$PROVIDER_CHOICE" = "0" ]; then
        write_env "CLOUD_PROVIDER" "openai"
        write_env "CLOUD_MODEL" "$(ask "Model" "gpt-4o")"
        write_env "OPENAI_API_KEY" "$(ask_secret "OpenAI API key")"
        write_env "ANTHROPIC_API_KEY" ""
    else
        write_env "CLOUD_PROVIDER" "anthropic"
        write_env "CLOUD_MODEL" "$(ask "Model" "claude-sonnet-4-6")"
        write_env "ANTHROPIC_API_KEY" "$(ask_secret "Anthropic API key")"
        write_env "OPENAI_API_KEY" ""
    fi
else
    write_env "LLM_MODE" "local"
    write_env "REASONER_MODEL" "qwen3:14b"
    write_env "ROUTER_MODEL" "qwen3:1.7b"
    echo -e "${GREEN}Local mode configured. Models will be pulled on first start.${NC}"
fi

# Splunk
print_section "Splunk"
echo -e "  ${BOLD}0${NC}  Containerized  (zero setup, synthetic demo data included)"
echo -e "  ${BOLD}1${NC}  External       (your existing Splunk instance)"
echo -e "  ${BOLD}2${NC}  Both           (configure external now, containerized available via make up-splunk)"
SPLUNK_CHOICE=$(ask "Select Splunk mode" "0")

if [ "$SPLUNK_CHOICE" = "1" ] || [ "$SPLUNK_CHOICE" = "2" ]; then
    write_env "SPLUNK_HOST" "$(ask "Splunk host" "localhost")"
    write_env "SPLUNK_PORT" "$(ask "Management port" "8089")"
    write_env "SPLUNK_TOKEN" "$(ask_secret "Splunk MCP token")"
    write_env "SPLUNK_TOKEN_FILE" "/splunk-shared/splunk_token"
    write_env "SPLUNK_VERIFY_SSL" "false"
    echo -e "${GREEN}External Splunk configured.${NC}"
fi

if [ "$SPLUNK_CHOICE" = "0" ] || [ "$SPLUNK_CHOICE" = "2" ]; then
    write_env "SPLUNK_PASSWORD" "$(ask "Containerized Splunk admin password" "changeme123!")"
    if [ "$SPLUNK_CHOICE" = "0" ]; then
        write_env "SPLUNK_HOST" "localhost"
        write_env "SPLUNK_PORT" "8089"
        write_env "SPLUNK_TOKEN" ""
        write_env "SPLUNK_TOKEN_FILE" "/splunk-shared/splunk_token"
        write_env "SPLUNK_VERIFY_SSL" "false"
    fi
    echo -e "${GREEN}Containerized Splunk configured. Run: make up-splunk${NC}"
fi

# Database and Auth
print_section "Database and Auth"

write_env "POSTGRES_DB" "soc_triage"
write_env "POSTGRES_USER" "postgres"
write_env "POSTGRES_PASSWORD" "$(gen_password)"
write_env "AUTH_APP_PASSWORD" "$(gen_password)"
write_env "AUDIT_WRITER_PASSWORD" "$(gen_password)"
write_env "AUDIT_READER_PASSWORD" "$(gen_password)"
write_env "ADMIN_EMAIL" "$(ask "Admin email" "admin@triagasoar.local")"

mkdir -p secrets

ADMIN_PASSWORD=""
while [ ${#ADMIN_PASSWORD} -lt 12 ]; do
    if [ -n "$ADMIN_PASSWORD" ]; then
        echo -e "${RED}Password must be at least 12 characters.${NC}"
    fi
    ADMIN_PASSWORD=$(ask_secret "Admin password (min 12 chars)")
done
printf '%s' "$ADMIN_PASSWORD" > secrets/admin_password.txt
printf '%s' "$(openssl rand -hex 32)" > secrets/session_secret.txt
chmod 600 secrets/admin_password.txt secrets/session_secret.txt
echo -e "${GREEN}Secrets written to secrets/${NC}"

# Velociraptor
print_section "Velociraptor (DFIR endpoint hunting)"
if ask_yn "Enable Velociraptor?"; then
    write_env "VELOCIRAPTOR_ENABLED" "true"
    write_env "VELOX_USER" "admin"
    write_env "VELOX_PASSWORD" "$(ask "Velociraptor admin password" "changeme123!")"
    write_env "VELOX_FRONTEND_HOSTNAME" "localhost"
    echo -e "${GREEN}Velociraptor enabled. Run: make up-velociraptor && make velociraptor-setup${NC}"
else
    write_env "VELOCIRAPTOR_ENABLED" "false"
fi

# Entra ID
print_section "Microsoft Entra ID (optional)"
if ask_yn "Integrate Entra ID?"; then
    write_env "ENTRA_TENANT_ID" "$(ask "Tenant ID")"
    write_env "ENTRA_CLIENT_ID" "$(ask "Client ID")"
    write_env "ENTRA_CLIENT_SECRET" "$(ask_secret "Client secret")"
    echo -e "${GREEN}Entra ID configured.${NC}"
else
    write_env "ENTRA_TENANT_ID" ""
    write_env "ENTRA_CLIENT_ID" ""
    write_env "ENTRA_CLIENT_SECRET" ""
fi

# Okta
print_section "Okta (optional)"
if ask_yn "Integrate Okta?"; then
    write_env "OKTA_DOMAIN" "$(ask "Okta domain (e.g. company.okta.com)")"
    write_env "OKTA_API_TOKEN" "$(ask_secret "API token")"
    echo -e "${GREEN}Okta configured.${NC}"
else
    write_env "OKTA_DOMAIN" ""
    write_env "OKTA_API_TOKEN" ""
fi

# Auth0
print_section "Auth0 (optional)"
if ask_yn "Integrate Auth0?"; then
    write_env "AUTH0_DOMAIN" "$(ask "Auth0 domain (e.g. company.auth0.com)")"
    write_env "AUTH0_CLIENT_ID" "$(ask "Client ID")"
    write_env "AUTH0_CLIENT_SECRET" "$(ask_secret "Client secret")"
    echo -e "${GREEN}Auth0 configured.${NC}"
else
    write_env "AUTH0_DOMAIN" ""
    write_env "AUTH0_CLIENT_ID" ""
    write_env "AUTH0_CLIENT_SECRET" ""
fi

# AbuseIPDB
print_section "Threat Intelligence (optional)"
if ask_yn "Add AbuseIPDB key? (free at abuseipdb.com/register)"; then
    write_env "ABUSEIPDB_API_KEY" "$(ask_secret "AbuseIPDB API key")"
    echo -e "${GREEN}AbuseIPDB configured.${NC}"
else
    write_env "ABUSEIPDB_API_KEY" ""
fi

# Teams
print_section "Teams Notifications (optional)"
if ask_yn "Add Teams webhook for playbook alerts?"; then
    write_env "TEAMS_WEBHOOK_URL" "$(ask "Webhook URL")"
    echo -e "${GREEN}Teams webhook configured.${NC}"
else
    write_env "TEAMS_WEBHOOK_URL" ""
fi

# Monitor
print_section "Background Monitor"
if ask_yn "Enable background Splunk alert monitor?" "y"; then
    write_env "MONITOR_ENABLED" "true"
    write_env "MONITOR_INTERVAL_SECONDS" "$(ask "Poll interval in seconds" "60")"
    write_env "MONITOR_COOLDOWN_MINUTES" "$(ask "Cooldown between alerts in minutes" "5")"
else
    write_env "MONITOR_ENABLED" "false"
    write_env "MONITOR_INTERVAL_SECONDS" "60"
    write_env "MONITOR_COOLDOWN_MINUTES" "5"
fi

# Done
echo ""
echo -e "${CYAN}${BOLD}-----------------------------------------${NC}"
echo -e "${GREEN}${BOLD}Setup complete!${NC}"
echo ""
echo -e "  .env written"
echo -e "  secrets/ generated"
echo ""
if [ "$LLM_CHOICE" = "1" ]; then
    echo -e "  Start: ${BOLD}make up-cloud${NC}"
else
    echo -e "  Start: ${BOLD}make up${NC}"
fi
if [ "$SPLUNK_CHOICE" = "0" ] || [ "$SPLUNK_CHOICE" = "2" ]; then
    echo -e "  Splunk: ${BOLD}make up-splunk${NC}"
fi
if [ "${VELOCIRAPTOR_ENABLED:-false}" = "true" ]; then
    echo -e "  Velociraptor: ${BOLD}make up-velociraptor && make velociraptor-setup${NC}"
fi
echo ""