"""
Authorization Module for MCP Server.

This module provides authentication and authorization functionality for the MCP server,
including token validation against Splunk's authentication endpoints and CUI token exchange.
"""

import base64
import fnmatch
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Set, Tuple
from urllib.parse import urljoin

import requests
import rsa
from constants import GRANT_TYPE_TOKEN_EXCHANGE, TOKEN_TYPE_ACCESS_TOKEN
from crypto import TokenCrypto
from logging_config import get_logger, update_log_context
from settings import MCPSettings
from splunk_api import call_splunk_api

# Module logger
logger = get_logger(__name__)

_CACHE_TTL_SECONDS = 300
_CUI_TOKEN_CACHE: Dict[Tuple[bytes, str], Tuple[str, float]] = {}
_JWT_ALG_TO_RSA_HASH = {
    "RS256": "SHA-256",
    "RS384": "SHA-384",
    "RS512": "SHA-512",
}


def _decode_jwt_no_verify(token: str) -> Dict[str, Any]:
    """
    Decode a JWT payload without verifying the signature.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT structure")

    payload_segment = parts[1]
    padding = "=" * (-len(payload_segment) % 4)
    payload_bytes = base64.urlsafe_b64decode(payload_segment + padding)
    payload = json.loads(payload_bytes.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Invalid JWT payload")
    return payload


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _decode_jwt_header_payload_no_verify(
    token: str,
) -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
    parts = token.split(".")
    if len(parts) != 3:
        return None

    try:
        header_segment = parts[0]
        payload_segment = parts[1]
        header_padding = "=" * (-len(header_segment) % 4)
        payload_padding = "=" * (-len(payload_segment) % 4)
        header_bytes = base64.urlsafe_b64decode(header_segment + header_padding)
        payload_bytes = base64.urlsafe_b64decode(payload_segment + payload_padding)
        header = json.loads(header_bytes.decode("utf-8"))
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return None

    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None

    return header, payload


def _is_sis_token(token: str) -> bool:
    decoded = _decode_jwt_header_payload_no_verify(token)
    if not decoded:
        return False

    header, payload = decoded
    token_type = header.get("token_type")
    if isinstance(token_type, str) and token_type.lower() == "sis":
        return True

    issuer = payload.get("iss")
    if isinstance(issuer, str) and "/sis" in issuer:
        return True

    return False


def _extract_tenant_id(token: str) -> Optional[str]:
    """
    Decode a JWT without verification and pull out the tenant identifier.

    Returns the value of a common tenant claim if present, otherwise None.
    """
    if not token:
        return None

    try:
        payload = _decode_jwt_no_verify(token)
    except Exception:
        return None

    for key in ("tenant_id", "tenantId", "tid", "tenant", "realm"):
        tenant_val = payload.get(key)
        if tenant_val:
            return str(tenant_val)
    return None


def _is_cui_issuer(issuer: str) -> bool:
    """Check if issuer matches the expected Webex CUI patterns."""
    normalized = issuer.rstrip("/")
    return fnmatch.fnmatch(normalized, "https://idbroker*.webex.com/idb*")


def _normalize_string_set(values: Any) -> Set[str]:
    if isinstance(values, str):
        return {v.strip() for v in values.split(",") if v.strip()}
    if isinstance(values, (list, tuple, set)):
        return {str(v).strip() for v in values if str(v).strip()}
    return set()


def _aud_matches_allowed(aud_claim: Any, allowed_audiences: Set[str]) -> bool:
    if isinstance(aud_claim, str):
        return aud_claim in allowed_audiences
    if isinstance(aud_claim, (list, tuple, set)):
        for entry in aud_claim:
            if isinstance(entry, str) and entry in allowed_audiences:
                return True
    return False


def _resolve_cui_jwks_url(settings: MCPSettings, issuer: str) -> str:
    jwks_by_issuer = getattr(settings, "cui_jwks_by_issuer", {}) or {}
    if isinstance(jwks_by_issuer, dict):
        override = jwks_by_issuer.get(issuer)
        if isinstance(override, str) and override.strip():
            return override.strip()
    return f"{issuer.rstrip('/')}/oauth2/v1/keys"


def _load_jwk_for_kid(
    settings: MCPSettings, issuer: str, kid: str
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    jwks_url = _resolve_cui_jwks_url(settings, issuer)
    try:
        response = requests.get(jwks_url, timeout=settings.timeout, verify=True)
    except requests.RequestException as e:
        return None, f"Failed to fetch JWKS: {e}"

    if response.status_code != 200:
        return None, f"JWKS fetch failed with status {response.status_code}"

    try:
        payload = response.json()
    except Exception as e:
        return None, f"Invalid JWKS response: {e}"

    keys = payload.get("keys")
    if not isinstance(keys, list):
        return None, "JWKS response missing 'keys' array"

    for key in keys:
        if not isinstance(key, dict):
            continue
        if key.get("kid") == kid:
            return key, None

    return None, "No JWKS key matched token kid"


def _public_key_from_jwk(
    jwk: Dict[str, Any]
) -> Tuple[Optional[rsa.PublicKey], Optional[str]]:
    if jwk.get("kty") != "RSA":
        return None, "JWK kty must be RSA"

    modulus = jwk.get("n")
    exponent = jwk.get("e")
    if not isinstance(modulus, str) or not isinstance(exponent, str):
        return None, "JWK is missing RSA modulus/exponent"

    try:
        n_int = int.from_bytes(_b64url_decode(modulus), byteorder="big")
        e_int = int.from_bytes(_b64url_decode(exponent), byteorder="big")
        return rsa.PublicKey(n_int, e_int), None
    except Exception as e:
        return None, f"Failed to parse RSA key from JWK: {e}"


def _validate_cui_jwt(
    auth_token: str,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    parts = auth_token.split(".")
    if len(parts) != 3:
        logger.info(
            "CUI JWT validation failed: invalid JWT structure (expected 3 parts, got %d)",
            len(parts),
        )
        return False, None, "Invalid JWT structure"

    try:
        header_raw, payload_raw, signature_raw = parts
        header = json.loads(_b64url_decode(header_raw).decode("utf-8"))
        payload = json.loads(_b64url_decode(payload_raw).decode("utf-8"))
    except Exception as e:
        logger.info("CUI JWT validation failed: could not decode JWT encoding: %s", e)
        return False, None, f"Invalid JWT encoding: {e}"

    if not isinstance(header, dict) or not isinstance(payload, dict):
        logger.info("CUI JWT validation failed: header or payload is not a JSON object")
        return False, None, "JWT header/payload must be JSON objects"

    alg = header.get("alg")
    if not isinstance(alg, str):
        logger.info("CUI JWT validation failed: missing alg in header")
        return False, None, "JWT header missing alg"

    normalized_alg = alg.upper()
    if normalized_alg == "NONE":
        logger.info("CUI JWT validation failed: unsigned JWTs are not allowed")
        return False, None, "Unsigned JWTs are not allowed"

    issuer = payload.get("iss")
    if not isinstance(issuer, str) or not issuer.strip():
        logger.info("CUI JWT validation failed: missing or empty issuer claim")
        return False, None, "JWT missing issuer claim"
    issuer = issuer.rstrip("/")

    if not _is_cui_issuer(issuer):
        logger.info("CUI JWT validation failed: issuer does not match CUI pattern")
        return False, None, "JWT issuer is not a recognised CUI issuer"
    logger.info("CUI JWT issuer check passed (pattern fallback)")
    return True, payload, None


def _hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def _get_cache_key(token: str, tenant_id: Optional[str]) -> Tuple[bytes, str]:
    return _hash_token(token), tenant_id or ""


def _get_cached_token(cache_key: Tuple[bytes, str]) -> Optional[str]:
    cached = _CUI_TOKEN_CACHE.get(cache_key)
    if not cached:
        return None
    value, expires_at = cached
    if expires_at < time.time():
        _CUI_TOKEN_CACHE.pop(cache_key, None)
        return None
    return value


def _set_cached_token(cache_key: Tuple[bytes, str], value: str) -> None:
    _CUI_TOKEN_CACHE[cache_key] = (value, time.time() + _CACHE_TTL_SECONDS)


def exchange_cui_token(
    auth_token: str, tenant_id: Optional[str] = None
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Exchange a Webex CUI JWT for a Splunk access token.

    Returns (success flag, exchanged token if any, error message if any).
    On success, sets ``client_id`` in the log context automatically.
    """
    log_extra = {"tenant_id": tenant_id}

    if not auth_token:
        logger.warning("No CUI token provided for exchange", extra=log_extra)
        return False, None, "No bearer token provided"

    try:
        payload = _decode_jwt_no_verify(auth_token)
    except Exception as e:
        # If we cannot decode, treat it as a non-CUI token and let normal auth flow continue
        logger.info(
            "CUI token decode failed, treating as non-CUI: %s", e, extra=log_extra
        )
        return False, None, "Not a CUI token"

    issuer = str(payload.get("iss", "")).rstrip("/")
    if not _is_cui_issuer(issuer):
        return False, None, "Not a CUI token"

    settings = MCPSettings.get()
    if getattr(settings, "cui_enforce_jwt_validation", True):
        is_valid_cui_jwt, verified_payload, validation_error = _validate_cui_jwt(
            auth_token
        )
        if not is_valid_cui_jwt:
            logger.warning(
                "CUI JWT validation failed: %s", validation_error, extra=log_extra
            )
            return False, None, f"CUI token validation failed: {validation_error}"
        payload = verified_payload or payload

    tenant_id = tenant_id or _extract_tenant_id(auth_token)
    log_extra["tenant_id"] = tenant_id

    client_id = payload.get("client_id")
    if not client_id:
        logger.error("Missing client_id in CUI token", extra=log_extra)
        return False, None, "Missing client_id in CUI token"

    cache_key = _get_cache_key(auth_token, tenant_id)
    cached = _get_cached_token(cache_key)
    if cached:
        update_log_context(client_id=str(client_id))
        return True, cached, None

    token_endpoint = urljoin(settings.splunkd_url, "oauth2/v1/token")

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
        "subject_token": auth_token,
        "subject_token_type": TOKEN_TYPE_ACCESS_TOKEN,
        "requested_token_type": TOKEN_TYPE_ACCESS_TOKEN,
    }

    try:
        # TLS verification is disabled because this is a local call to
        # splunkd, which uses a self-signed certificate by default.

        # nosemgrep: tools.semgrep.rules.CCF.disabled-cert-validation
        response = requests.post(token_endpoint, headers=headers, data=data, timeout=settings.timeout, verify=False)  # fmt: skip

    except requests.RequestException as e:
        logger.exception("CUI token exchange request failed", extra=log_extra)
        logger.info("CUI token exchange request error: %s", e, extra=log_extra)
        return False, None, f"Token exchange error: {e}"

    if response.status_code != 200:
        logger.error(
            "CUI token exchange failed with status %d: %s",
            response.status_code,
            response.text,
            extra=log_extra,
        )
        return False, None, "Token exchange failed"

    try:
        response_data = response.json()
        exchanged_token = response_data.get("access_token")
    except Exception as e:
        logger.error("Failed to parse token exchange response: %s", e, extra=log_extra)
        return False, None, "Invalid token exchange response"

    if not exchanged_token:
        logger.error("access_token missing in token exchange response", extra=log_extra)
        return False, None, "Token exchange response missing access_token"

    _set_cached_token(cache_key, exchanged_token)
    logger.info("Successfully exchanged CUI token", extra=log_extra)
    update_log_context(client_id=str(client_id))
    return True, exchanged_token, None


def _initialize_token_crypto(
    system_authtoken: Optional[str], log_extra: Dict[str, Any]
) -> bool:
    if not system_authtoken:
        logger.error("Missing system authtoken for token crypto init", extra=log_extra)
        return False

    tc = TokenCrypto.get_instance()
    try:
        settings = MCPSettings.get()
        tc.configure_reload_interval(settings.token_key_reload_interval_seconds)
    except Exception:
        # Crypto should still try to initialize even if settings are unavailable.
        pass

    if not tc.initialize(system_authtoken):
        logger.error("Failed to initialize TokenCrypto", extra=log_extra)
        return False

    return True


class MCPAuthorization:
    """
    Handles MCP server authorization and token validation.

    This class provides methods to validate authentication tokens against
    Splunk's authentication endpoints and manage authorization state.
    """

    @staticmethod
    def validate_token(
        auth_token: str,
        system_authtoken: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]], Optional[str], bool]:
        """
        Validate an authentication token using Splunk's current-context endpoint.

        This method calls the Splunk REST API endpoint services/authentication/current-context
        to validate the provided session key and retrieve user context information.

        Args:
            auth_token: The authentication token to validate.
            system_authtoken: System token for initializing encryption keys when needed.

        Returns:
            Tuple containing:
                - bool: True if token is valid, False otherwise
                - Optional[str]: Original or decrypted token
                - Optional[Dict[str, Any]]: User context information if successful, None if failed
                - Optional[str]: Error message if validation failed, None if successful
                - bool: True if the token was obtained via CUI exchange
        """
        logger.info("Validating authentication token")
        tenant_id = _extract_tenant_id(auth_token)
        log_extra = {"tenant_id": tenant_id}
        was_cui_exchange = False

        if not auth_token:
            logger.warning(
                "Empty or None session key provided for validation", extra=log_extra
            )
            return False, None, None, "No bearer token provided", was_cui_exchange

        # If this is a CUI token, exchange it for a Splunk token before validation
        cui_ok, exchanged_token, cui_error = exchange_cui_token(auth_token, tenant_id)
        if cui_ok and exchanged_token:
            auth_token = exchanged_token
            tenant_id = tenant_id or _extract_tenant_id(auth_token)
            log_extra["tenant_id"] = tenant_id
            was_cui_exchange = True
        elif cui_error and cui_error != "Not a CUI token":
            logger.warning("CUI token exchange failed: %s", cui_error, extra=log_extra)
            return (
                False,
                None,
                None,
                f"Authentication failed: {cui_error}",
                was_cui_exchange,
            )

        # Decrypt auth token if needed.
        # Tokens returned from a successful CUI exchange are treated as trusted
        # Splunk-issued bearer tokens and are not forced through encrypted-token
        # decryption enforcement.
        is_sis_token = _is_sis_token(auth_token)
        if is_sis_token:
            try:
                sis_payload = _decode_jwt_no_verify(auth_token)
                update_log_context(client_id=sis_payload.get("client_id"))
            except Exception:
                pass
        if not is_sis_token and not was_cui_exchange:
            settings = MCPSettings.get()
            crypto_ready = _initialize_token_crypto(system_authtoken, log_extra)
            if crypto_ready:
                try:
                    auth_token = TokenCrypto.get_instance().decrypt(auth_token)
                    tenant_id = tenant_id or _extract_tenant_id(auth_token)
                    log_extra["tenant_id"] = tenant_id
                except ValueError as e:
                    # If encryption is required, reject
                    settings = MCPSettings.get()
                    if settings.require_encrypted_token:
                        if MCPAuthorization._legacy_plaintext_allowed(settings):
                            logger.warning(
                                "Allowing legacy plaintext token during grace window.",
                                extra=log_extra,
                            )
                        else:
                            logger.warning(
                                "Encrypted token required but decryption failed: %s",
                                e,
                                extra=log_extra,
                            )
                            return (
                                False,
                                None,
                                None,
                                "Authentication failed: encrypted token required",
                                was_cui_exchange,
                            )
            elif settings.require_encrypted_token:
                if MCPAuthorization._legacy_plaintext_allowed(settings):
                    logger.warning(
                        "Allowing legacy plaintext token during grace window.",
                        extra=log_extra,
                    )
                else:
                    logger.warning(
                        "Encrypted token required but crypto initialization failed",
                        extra=log_extra,
                    )
                    return (
                        False,
                        None,
                        None,
                        "Authentication failed: encrypted token required",
                        was_cui_exchange,
                    )

        try:
            # Call Splunk's current-context endpoint to validate the token
            response = call_splunk_api(
                session_key=auth_token,
                method="GET",
                api="services/authentication/current-context",
                params={"output_mode": "json"},
            )

            if response.status_code == 200:
                try:
                    context_data = response.json()

                    # Extract user information from the response
                    entry = context_data.get("entry", [{}])
                    if entry:
                        content = entry[0].get("content", {})
                        user_info = {
                            "username": content.get("username"),
                            "email": content.get("email"),
                            "realname": content.get("realname"),
                            "roles": content.get("roles", []),
                            "capabilities": content.get("capabilities", []),
                        }

                        logger.info(
                            "Token validation successful for user: %s",
                            user_info.get("username", "unknown"),
                        )
                        update_log_context(
                            auth_method=(
                                "oauth" if was_cui_exchange or is_sis_token else "token"
                            ),
                        )
                        return True, auth_token, user_info, None, was_cui_exchange
                    else:
                        logger.error(
                            "No entry found in current-context response",
                            extra=log_extra,
                        )
                        return (
                            False,
                            None,
                            None,
                            "Invalid response format from authentication endpoint",
                            was_cui_exchange,
                        )

                except Exception as e:
                    logger.error(
                        "Failed to parse current-context response: %s",
                        e,
                        extra=log_extra,
                    )
                    return (
                        False,
                        None,
                        None,
                        f"Failed to parse authentication response: {e}",
                        was_cui_exchange,
                    )

            elif response.status_code == 401:
                logger.warning(
                    "Token validation failed - unauthorized", extra=log_extra
                )
                return False, None, None, "Invalid or expired token", was_cui_exchange

            elif response.status_code == 403:
                logger.warning("Token validation failed - forbidden", extra=log_extra)
                return False, None, None, "Access denied for token", was_cui_exchange

            else:
                logger.error(
                    "Token validation failed with status %d: %s",
                    response.status_code,
                    response.text,
                    extra=log_extra,
                )
                return (
                    False,
                    None,
                    None,
                    f"Authentication endpoint error: {response.status_code}",
                    was_cui_exchange,
                )

        except Exception as e:
            logger.exception(
                "Unexpected error during token validation: %s", e, extra=log_extra
            )
            return False, None, None, f"Token validation error: {e}", was_cui_exchange

    @staticmethod
    def _legacy_plaintext_allowed(settings: MCPSettings) -> bool:
        grace_days = getattr(settings, "legacy_token_grace_days", 0)
        if grace_days <= 0:
            return False

        token_crypto = TokenCrypto.get_instance()
        created_at = getattr(token_crypto, "private_key_created_at", None)
        parsed_created_at = MCPAuthorization._parse_iso8601_utc(created_at)
        if parsed_created_at is None:
            return False

        return datetime.now(timezone.utc) <= (
            parsed_created_at + timedelta(days=int(grace_days))
        )

    @staticmethod
    def _parse_iso8601_utc(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            normalized = value
            if normalized.endswith("Z"):
                normalized = f"{normalized[:-1]}+00:00"
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            return None

    @staticmethod
    def check_user_capabilities(
        user_info: Dict[str, Any], required_capabilities: list = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if a user has required capabilities.

        Args:
            user_info: User information dictionary from validate_token
            required_capabilities: List of required capabilities. If None, only checks if user is valid.

        Returns:
            Tuple containing:
                - bool: True if user has required capabilities, False otherwise
                - Optional[str]: Error message if check failed, None if successful
        """
        if not user_info:
            return False, "No user information provided"

        username = user_info.get("username")
        if not username:
            return False, "No username found in user information"

        if required_capabilities is None:
            # No specific capabilities required, just need valid user
            return True, None

        user_capabilities = user_info.get("capabilities", [])

        for required_cap in required_capabilities:
            if required_cap not in user_capabilities:
                logger.warning(
                    "User %s missing required capability: %s", username, required_cap
                )
                return False, f"Missing required capability: {required_cap}"

        logger.info(
            "User %s has all required capabilities: %s", username, required_capabilities
        )
        return True, None


# Public API exports
__all__ = [
    "MCPAuthorization",
    "exchange_cui_token",
]
