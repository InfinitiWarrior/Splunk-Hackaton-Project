# soc-agent/velociraptor.py
# Velociraptor integration — dispatch hunts and collect endpoint telemetry
# Uses docker exec to call the Velociraptor binary directly, bypassing gRPC TLS issues
import os
import json
import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)

VELO_CONTAINER = os.getenv("VELOCIRAPTOR_CONTAINER", "velociraptor")
VELO_API_CONFIG = os.getenv("VELOCIRAPTOR_API_CONFIG", "/velociraptor-shared/api.config.yaml")
VELO_ENABLED = os.getenv("VELOCIRAPTOR_ENABLED", "false").lower() == "true"
VELO_BIN = "/velociraptor/velociraptor"
# Inside the Velociraptor container, the shared volume is mounted at /shared
VELO_CONTAINER_CONFIG = "/shared/api.config.yaml"

# Artifacts to collect per investigation type
HUNT_ARTIFACTS = {
    "brute_force": [
        "Linux.Sys.Users",
        "Linux.Sys.LastUserLogin",
        "Linux.Sys.BashHistory",
    ],
    "credential_stuffing": [
        "Linux.Sys.Users",
        "Linux.Sys.LastUserLogin",
    ],
    "lateral_movement": [
        "Linux.Network.NetstatEnriched",
        "Linux.Sys.BashHistory",
        "Linux.Sys.Pslist",
        "Linux.Sys.Crontab",
    ],
    "privilege_escalation": [
        "Linux.Sys.Pslist",
        "Linux.Sys.BashHistory",
        "Linux.Sys.Crontab",
    ],
    "default": [
        "Linux.Sys.Pslist",
        "Linux.Network.Netstat",
    ],
}


def velo_available() -> bool:
    if not VELO_ENABLED:
        return False
    if not os.path.exists(VELO_API_CONFIG):
        logger.warning("Velociraptor API config not found at %s", VELO_API_CONFIG)
        return False
    return True


async def _velo_query(vql: str) -> list[dict]:
    """Run a VQL query via docker exec into the Velociraptor container."""
    cmd = [
        "docker", "exec", VELO_CONTAINER,
        VELO_BIN,
        "--api_config", VELO_CONTAINER_CONFIG,
        "query", vql,
        "--format", "json",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        if proc.returncode != 0:
            logger.error("Velociraptor query error: %s", stderr.decode())
            return []
        output = stdout.decode().strip()
        if not output:
            return []
        return json.loads(output)
    except asyncio.TimeoutError:
        logger.error("Velociraptor query timed out")
        return []
    except Exception as e:
        logger.error("Velociraptor query exception: %s", e)
        return []


async def find_client(hostname_or_ip: str) -> Optional[str]:
    """Find a Velociraptor client ID by hostname or IP."""
    if not velo_available():
        return None
    vql = f"SELECT client_id FROM clients() WHERE os_info.hostname =~ '{hostname_or_ip}' OR last_ip =~ '{hostname_or_ip}' LIMIT 1"
    results = await _velo_query(vql)
    if results:
        return results[0].get("client_id")
    return None


async def collect_artifact(
    client_id: str,
    artifact: str,
    timeout: int = 120,
) -> list[dict]:
    """Dispatch a collection on a specific client and wait for results."""
    if not velo_available():
        return []

    # Schedule and wait for collection in one VQL
    vql = (
        f"LET flow = collect_client(client_id='{client_id}', artifacts=['{artifact}']) "
        f"SELECT * FROM source(client_id='{client_id}', flow_id=flow.flow_id, artifact='{artifact}')"
    )
    return await _velo_query(vql)


async def hunt_host(
    hostname_or_ip: str,
    alert_type: str = "default",
) -> dict:
    """Find a host, dispatch relevant artifact collections, return results."""
    if not velo_available():
        return {"available": False}

    client_id = await find_client(hostname_or_ip)
    if not client_id:
        logger.info("No Velociraptor client found for %s", hostname_or_ip)
        return {"available": True, "client_found": False, "host": hostname_or_ip}

    artifacts = HUNT_ARTIFACTS.get(alert_type, HUNT_ARTIFACTS["default"])
    collected = {}

    for artifact in artifacts:
        logger.info("Collecting %s from %s (%s)", artifact, hostname_or_ip, client_id)
        results = await collect_artifact(client_id, artifact)
        if results:
            collected[artifact] = results[:20]

    return {
        "available": True,
        "client_found": True,
        "client_id": client_id,
        "host": hostname_or_ip,
        "artifacts_collected": list(collected.keys()),
        "results": collected,
    }


async def create_hunt(
    artifact: str,
    description: str = "",
    parameters: dict = None,
) -> Optional[str]:
    """Create a fleet-wide hunt and return the hunt ID."""
    if not velo_available():
        return None
    vql = f"SELECT hunt(description='{description}', artifacts=['{artifact}']) AS H FROM scope()"
    results = await _velo_query(vql)
    if results:
        h = results[0].get("H", {})
        hunt_id = h.get("HuntId") or (h.get("Request") or {}).get("hunt_id")
        if hunt_id:
            logger.info("Velociraptor hunt %s created for %s", hunt_id, artifact)
            return hunt_id
    return None


async def get_clients() -> list[dict]:
    """List all known Velociraptor clients."""
    if not velo_available():
        return []
    vql = "SELECT client_id, os_info.hostname AS hostname, last_ip, os_info.system AS os FROM clients() LIMIT 100"
    return await _velo_query(vql)