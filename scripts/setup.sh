.PHONY: setup up up-cloud up-splunk up-velociraptor down rebuild rebuild-cloud \
        splunk-setup splunk-token velociraptor-setup \
        demo reset-db logs attack query pull-models

# ── Setup wizard ──────────────────────────────────────────────────────────
setup:
	@bash scripts/setup.sh

# ── Local mode (Ollama on GPU) ────────────────────────────────────────────
up:
	sudo docker compose --profile cloud down 2>/dev/null || true
	sudo docker compose --profile local up --remove-orphans -d
	sudo docker exec ollama ollama pull qwen3:14b
	sudo docker exec ollama ollama pull qwen3:1.7b
	sudo docker compose --profile local logs -f

# ── Cloud mode (OpenAI / Anthropic API) ──────────────────────────────────
up-cloud:
	sudo docker compose --profile local down 2>/dev/null || true
	sudo docker compose --profile cloud up --remove-orphans -d
	sudo docker compose --profile cloud logs -f

# ── Splunk self-contained mode ────────────────────────────────────────────
up-splunk:
	sudo docker compose --profile local --profile splunk up --remove-orphans -d
	@echo "Waiting for Splunk to be healthy (3-5 min)..."
	@until sudo docker inspect splunk --format='{{.State.Health.Status}}' 2>/dev/null | grep -q healthy; do sleep 10; printf '.'; done
	@echo " Splunk healthy"
	sudo docker exec splunk bash /setup.sh
	sudo docker exec splunk bash /seed.sh
	sudo docker compose --profile local --profile splunk logs -f

splunk-setup:
	@until sudo docker inspect splunk --format='{{.State.Health.Status}}' 2>/dev/null | grep -q healthy; do sleep 10; printf '.'; done
	sudo docker exec splunk bash /setup.sh
	sudo docker exec splunk bash /seed.sh

splunk-token:
	@sudo docker exec splunk cat /tmp/splunk_mcp_token 2>/dev/null || echo "Run make splunk-setup first"

# Switch to containerized Splunk (token read from shared volume)
use-splunk-container:
	sed -i 's|^SPLUNK_TOKEN=.*|SPLUNK_TOKEN=|' .env
	sed -i 's|^SPLUNK_TOKEN_FILE=.*|SPLUNK_TOKEN_FILE=/splunk-shared/splunk_token|' .env
	sudo docker restart soc-agent
	@echo "Switched to containerized Splunk"

# Switch to external Splunk (token from env var)
use-splunk-external:
	@read -p "Splunk MCP token: " TOKEN; \
	sed -i "s|^SPLUNK_TOKEN=.*|SPLUNK_TOKEN=$$TOKEN|" .env
	sed -i 's|^SPLUNK_TOKEN_FILE=.*|SPLUNK_TOKEN_FILE=|' .env
	sudo docker restart soc-agent
	@echo "Switched to external Splunk"

# ── Velociraptor ──────────────────────────────────────────────────────────
up-velociraptor:
	sudo docker compose --profile velociraptor up --remove-orphans -d velociraptor
	@echo "Waiting for Velociraptor to be healthy..."
	@until sudo docker inspect velociraptor --format='{{.State.Health.Status}}' 2>/dev/null | grep -q healthy; do sleep 5; printf '.'; done
	@echo " Velociraptor healthy"
	@echo "Run: make velociraptor-setup"

velociraptor-setup:
	sudo docker exec velociraptor /velociraptor/velociraptor \
		--config /velociraptor/server.config.yaml \
		config api_client \
		--name localhost \
		--role administrator \
		/shared/api.config.yaml
	@echo "API config written. Restart soc-agent: docker restart soc-agent"

# ── Stop everything ───────────────────────────────────────────────────────
down:
	sudo docker compose --profile local --profile cloud --profile splunk --profile velociraptor down

# ── Rebuild ───────────────────────────────────────────────────────────────
rebuild:
	sudo docker compose --profile cloud down 2>/dev/null || true
	sudo docker compose --profile local build
	sudo docker compose --profile local up --remove-orphans -d
	sudo docker compose --profile local logs -f

rebuild-cloud:
	sudo docker compose --profile local down 2>/dev/null || true
	sudo docker compose --profile cloud build
	sudo docker compose --profile cloud up --remove-orphans -d
	sudo docker compose --profile cloud logs -f

# ── Pull Ollama models ────────────────────────────────────────────────────
pull-models:
	sudo docker exec ollama ollama pull qwen3:14b
	sudo docker exec ollama ollama pull qwen3:1.7b

# ── Utilities ─────────────────────────────────────────────────────────────
reset-db:
	bash scripts/reset-db.sh

logs:
	sudo docker compose --profile local logs -f soc-agent 2>/dev/null || \
	sudo docker compose --profile cloud logs -f soc-agent

attack:
	bash scripts/attack-simulation.sh

query:
	bash scripts/splunk-query.sh $(Q)

demo:
	bash scripts/reset-db.sh
	sudo docker restart soc-agent
	bash scripts/demo.sh