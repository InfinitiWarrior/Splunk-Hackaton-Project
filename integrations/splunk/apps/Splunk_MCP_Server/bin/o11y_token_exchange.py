import json
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import requests
import splunklib.client
from constants import CONTENT, ENTRY, SENSITIVE_HEADERS
from logging_config import get_logger
from settings import MCPSettings

logger = get_logger(__name__)

O11Y_DOMAIN = "signalfx.com"

EC_AUTH_TOKEN_URL = "/services/authorization/tokens"
EC_TENANT_INFO_URL = "/services/server/scs/tenantinfo"

_O11Y_TOKEN_TTL_MS = 59 * 60 * 1000

# O11y API paths
O11Y_EXCHANGE_PATH = "/v2/splunk-integrations/_/o11y-access-token"
O11Y_PAIRING_INFO_PATH = "/v2/splunk-integrations/_/pairing-info"
O11Y_ORG_PATH = "/v2/organization"

_O11Y_REALMS: frozenset = frozenset({"lab0", "rc0"})

O11Y_ACCESS_TOKEN = "accessToken"
O11Y_ORG_ID = "organizationId"


class O11yExchangeError(Exception):
    pass


def _redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {
        k: "***" if k.lower() in SENSITIVE_HEADERS else v for k, v in headers.items()
    }


def _extract_entry_content(payload: Dict[str, Any]) -> Dict[str, Any]:
    entries = payload.get(ENTRY) or []
    if not entries or not isinstance(entries, list):
        raise O11yExchangeError("No entry content found")
    first = entries[0]
    if not isinstance(first, dict):
        raise O11yExchangeError("Invalid entry format")
    content = first.get(CONTENT)
    if not isinstance(content, dict):
        raise O11yExchangeError("Missing entry content")
    return content


def _get_ec_token(service: splunklib.client.Service) -> str:
    """Fetch an EC access token for the signed-in user."""
    try:
        response = service.post(
            EC_AUTH_TOKEN_URL, output_mode="json", type="interactive"
        )
    except splunklib.binding.HTTPError as exc:
        logger.info(
            "EC token request failed: status=%d reason=%s", exc.status, exc.reason
        )
        raise O11yExchangeError(f"EC token request failed: {exc.status} {exc.reason}")
    try:
        payload = json.loads(response.body.read())
    except Exception as exc:
        raise O11yExchangeError(f"Invalid EC token response: {exc}")
    content = _extract_entry_content(payload)
    token = content.get("token")
    if not token:
        raise O11yExchangeError("EC token missing")
    return str(token)


def _resolve_realms(
    tenant_info: Dict[str, Any],
) -> List[str]:
    """Return the list of o11y realms for this tenant."""
    o11y_pairings = tenant_info.get("o11yPairings")
    if isinstance(o11y_pairings, dict) and o11y_pairings:
        realms = {
            pairing.get("realm")
            for pairing in o11y_pairings.values()
            if isinstance(pairing, dict)
        }
        paired_realms = [realm for realm in realms if realm]
        if paired_realms:
            return paired_realms

    region = tenant_info.get("ecRegion")
    if isinstance(region, str) and region:
        return [region]

    return []


def _get_ec_tenant_info(service: splunklib.client.Service) -> Dict[str, Any]:
    """Fetch tenant metadata."""
    try:
        response = service.get(EC_TENANT_INFO_URL, output_mode="json")
    except splunklib.binding.HTTPError as exc:
        raise O11yExchangeError(f"EC tenant info failed: {exc.status} {exc.reason}")
    try:
        payload = json.loads(response.body.read())
    except Exception as exc:
        raise O11yExchangeError(f"Invalid tenant info response: {exc}")

    content = _extract_entry_content(payload)

    tenant_info = {
        "cloudStack": content.get("cloudStack"),
        "tenant": content.get("tenant"),
        "ecRegion": content.get("ecRegion"),
        "o11yPairings": content.get("o11yPairings") or {},
    }
    tenant_info["pairedO11yRealms"] = _resolve_realms(tenant_info)
    return tenant_info


def _http_request(
    method: str,
    url: str,
    headers: Dict[str, str],
    settings: MCPSettings,
) -> Tuple[int, Optional[Any]]:
    logger.info("O11y %s %s headers=%s", method, url, _redact_headers(headers))
    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            timeout=settings.timeout,
            verify=True,
        )
    except requests.RequestException as e:
        logger.error("O11y request failed: %s", e)
        return 503, None
    if not response.text:
        return response.status_code, None
    try:
        return response.status_code, response.json()
    except Exception:
        return response.status_code, None


def _build_o11y_url(realm: str, domain: str, path: str, params: str = "") -> str:
    """Build an O11y URL for the given ``realm``."""
    host_prefix = "private-api" if realm in _O11Y_REALMS else "api"
    base_url = f"https://{host_prefix}.{realm}.{domain}{path}"
    if params:
        return f"{base_url}?{params}"
    return base_url


def _call_o11y_exchange(
    ec_access_token: str,
    tenant: str,
    realm: str,
    domain: str,
    org_id: Optional[str],
    settings: MCPSettings,
) -> Optional[Dict[str, Any]]:
    """Exchange an EC access token for an O11y access token.

    Returns a dict with the o11y access token, its expiry, and the org id on
    success, or ``None`` on failure.
    """
    query: Dict[str, str] = {"tenant": tenant}
    if org_id:
        query["orgId"] = org_id
    url = _build_o11y_url(realm, domain, O11Y_EXCHANGE_PATH, urlencode(query))
    status, payload = _http_request(
        "POST",
        url,
        headers={"X-EC-Access-Token": ec_access_token},
        settings=settings,
    )
    if status != 201 or not isinstance(payload, dict):
        logger.warning("o11y token exchange failed: %s %s", status, payload)
        return None

    if not payload.get(O11Y_ACCESS_TOKEN) or not payload.get(O11Y_ORG_ID):
        logger.info("o11y tokenexchange response missing token/org id")
        return None

    expiry_ms = int(time.time() * 1000) + _O11Y_TOKEN_TTL_MS
    return {
        O11Y_ACCESS_TOKEN: payload.get(O11Y_ACCESS_TOKEN),
        "capabilities": payload.get("capabilities") or "",
        "expiryMs": int(expiry_ms),
        "o11yOrgId": payload.get(O11Y_ORG_ID),
        "realm": realm,
    }


def _call_o11y_org_url(
    access_token: str,
    ec_access_token: str,
    realm: str,
    domain: str,
    settings: MCPSettings,
) -> Optional[str]:
    """Fetch the O11y URL for the paired org.

    Returns the URL string on success, or ``None`` on any failure.
    """
    url = _build_o11y_url(realm, domain, O11Y_ORG_PATH)
    status, payload = _http_request(
        "GET",
        url,
        headers={
            "X-SF-Token": access_token,
            "X-EC-Access-Token": ec_access_token,
        },
        settings=settings,
    )
    if status != 200 or not isinstance(payload, dict):
        logger.warning("o11y org url fetch failed: %s %s", status, payload)
        return None
    return payload.get("url")


def _fetch_pairing_info(
    ec_access_token: str,
    tenant: str,
    ec_region: str,
    realm: str,
    domain: str,
    settings: MCPSettings,
    org_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Fetch pairing metadata for this tenant.

    When ``org_id`` is provided, returns the entry for that specific org.
    Otherwise returns the first paired org. Returns ``None`` when no matching
    pairing exists or the call fails.
    """
    url = _build_o11y_url(
        realm, domain, O11Y_PAIRING_INFO_PATH, urlencode({"tenant": tenant})
    )
    status, payload = _http_request(
        "GET",
        url,
        headers={"X-EC-Access-Token": ec_access_token},
        settings=settings,
    )
    if status != 200 or not isinstance(payload, list) or not payload:
        return None

    if org_id:
        org_data = next(
            (
                entry
                for entry in payload
                if isinstance(entry, dict) and entry.get(O11Y_ORG_ID) == org_id
            ),
            None,
        )
    else:
        org_data = payload[0]

    if not isinstance(org_data, dict):
        return None
    return {
        "o11yOrgId": org_data.get(O11Y_ORG_ID),
        "ecTenantName": org_data.get("organizationName"),
        "ecRegion": ec_region,
        "realm": realm,
        "pairingType": org_data.get("pairingType"),
        "orgUrl": org_data.get("orgUrl"),
    }


def get_user_o11y_token(
    service: splunklib.client.Service, org_id: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Mint a user-scoped Observability Cloud access token.

    Perform EC - O11y token excchange using the session token for the signed-in user
    and return a dict containing following fields:
    - ``o11yAccessToken``: the token itself plus its realm, expiry, and
      org id.
    - ``pairingInfo``: a one-element list describing the paired org
      (tenant name, org URL), or an empty list if no pairing was found.

    If ``org_id`` is provided, the exchange is scoped to that org, otherwise
    the user's first paired org is used. Returns ``None`` on any failure so
    the caller can fall back to ``services/o11y-tokens`` splunkd endpoint.
    """
    settings = MCPSettings.get()
    try:
        ec_access_token = _get_ec_token(service)
        tenant_info = _get_ec_tenant_info(service)
    except O11yExchangeError as exc:
        logger.info(
            "Skipping UID o11y exchange due to EC failure: %s — will fall back to services/o11y-tokens",
            exc,
        )
        return None

    tenant = tenant_info.get("tenant")
    realms = tenant_info.get("pairedO11yRealms") or []
    logger.info("EC tenant info retrieved: realm_count=%d", len(realms))
    if not tenant or not realms:
        logger.info(
            "Skipping o11y exchange due to missing tenant/realms — will fall back to services/o11y-tokens"
        )
        return None

    o11y_pairings = tenant_info.get("o11yPairings") or {}
    realm = None
    org_id_for_exchange = org_id

    if isinstance(o11y_pairings, dict) and o11y_pairings:
        if org_id:
            pairing = o11y_pairings.get(org_id)
            if isinstance(pairing, dict):
                realm = pairing.get("realm")
        else:
            first_org_id, pairing = next(iter(o11y_pairings.items()))
            if isinstance(pairing, dict):
                realm = pairing.get("realm")
                org_id_for_exchange = str(first_org_id)

    if not realm:
        realm = realms[0]

    logger.info("Attempting UID o11y exchange")
    exchange = _call_o11y_exchange(
        ec_access_token,
        tenant,
        realm,
        O11Y_DOMAIN,
        org_id_for_exchange,
        settings,
    )
    if not exchange:
        logger.info(
            "UID o11y exchange returned no result — will fall back to services/o11y-tokens"
        )
        return None
    logger.info("UID o11y exchange succeeded")

    exchange["ecAccessToken"] = ec_access_token
    org_url = _call_o11y_org_url(
        exchange.get(O11Y_ACCESS_TOKEN, ""),
        ec_access_token,
        realm,
        O11Y_DOMAIN,
        settings,
    )
    if org_url:
        exchange["o11yOrgUrl"] = org_url

    pairing_info = _fetch_pairing_info(
        ec_access_token,
        tenant,
        tenant_info.get("ecRegion") or "",
        realm,
        O11Y_DOMAIN,
        settings,
        org_id=org_id_for_exchange,
    )

    return {
        "o11yAccessToken": exchange,
        "pairingInfo": [pairing_info] if pairing_info else [],
    }
