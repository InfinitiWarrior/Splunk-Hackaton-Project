MESSAGES = "messages"
TYPE = "type"
TEXT = "text"
ERROR = "error"
CONTENT_TYPE_JSON = "application/json"

METHOD_NOT_ALLOWED = "Method not allowed"
INTERNAL_SERVER_ERROR = "Internal server error"

SPLUNK_MCP_SERVER_APP = "Splunk_MCP_Server"

# Splunk REST response keys
ENTRY = "entry"
CONTENT = "content"
ACL = "acl"
APP = "app"
DISABLED = "disabled"

SYSTEM_AUTHTOKEN = "system_authtoken"
SESSION = "session"
AUTHTOKEN = "authtoken"
SERVER = "server"
REST_URI = "rest_uri"

# OAuth 2.0 Token Exchange (RFC 8693)
GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"

TRACEPARENT_HEADER_NAME = "traceparent"
AUTHORIZATION_HEADER_NAME = "authorization"

# ---------------------------------------------------------------------------
# Conf file and stanza names
# ---------------------------------------------------------------------------
CONF_MCP = "mcp"
CONF_APP = "app"
STANZA_SERVER = "server"
STANZA_ID = "id"
STANZA_PACKAGE = "package"
STANZA_LAUNCHER = "launcher"

# ---------------------------------------------------------------------------
# mcp.conf [server] keys
# ---------------------------------------------------------------------------
CONF_KEY_TIMEOUT = "timeout"
CONF_KEY_MAX_ROW_LIMIT = "max_row_limit"
CONF_KEY_DEFAULT_ROW_LIMIT = "default_row_limit"
CONF_KEY_REQUIRE_ENCRYPTED_TOKEN = "require_encrypted_token"
CONF_KEY_LEGACY_TOKEN_GRACE_DAYS = "legacy_token_grace_days"
CONF_KEY_TOKEN_KEY_RELOAD_INTERVAL = "token_key_reload_interval_seconds"
CONF_KEY_MCP_TOKEN_MAX_LIFETIME = "mcp_token_max_lifetime_seconds"
CONF_KEY_MCP_TOKEN_DEFAULT_LIFETIME = "mcp_token_default_lifetime_seconds"
CONF_KEY_CUI_ENFORCE_JWT_VALIDATION = "cui_enforce_jwt_validation"
CONF_KEY_CUI_ALLOWED_ISSUERS = "cui_allowed_issuers"
CONF_KEY_CUI_ALLOWED_AUDIENCES = "cui_allowed_audiences"
CONF_KEY_CUI_ALLOWED_JWT_ALGS = "cui_allowed_jwt_algs"
CONF_KEY_CUI_JWKS_BY_ISSUER = "cui_jwks_by_issuer"
CONF_KEY_CUI_JWT_CLOCK_SKEW = "cui_jwt_clock_skew_seconds"

# ---------------------------------------------------------------------------
# app.conf keys
# ---------------------------------------------------------------------------
CONF_KEY_NAME = "name"
CONF_KEY_ID = "id"
CONF_KEY_TITLE = "title"
CONF_KEY_VERSION = "version"

# Telemetry event types — success
EVENT_AUTH_SUCCESS = "auth_success"
EVENT_INITIALIZE_COMPLETE = "initialize_complete"
EVENT_TOOLS_LIST_COMPLETE = "tools_list_complete"
EVENT_TOOL_CALL_COMPLETE = "tool_call_complete"
EVENT_NOTIFICATION_RECEIVED = "notification_received"

# Telemetry event types — admin / configuration
EVENT_TOOL_ENABLED = "tool_enabled"
EVENT_TOOL_DISABLED = "tool_disabled"

# Telemetry event types — failure / rejection
EVENT_AUTH_FAILURE = "auth_failure"
EVENT_AUTH_INVALID_AUDIENCE = "auth_invalid_audience"
EVENT_AUTH_TOKEN_DECODE_ERROR = "auth_token_decode_error"
EVENT_AUTH_ACCESS_DENIED = "auth_access_denied"
EVENT_TOOL_CALL_ERROR = "tool_call_error"
EVENT_RATE_LIMIT_REJECTED = "rate_limit_rejected"
EVENT_TOOL_RATE_LIMIT_EXCEEDED = "tool_rate_limit_exceeded"
EVENT_SPL_SAFETY_REJECTION = "spl_safety_rejection"
EVENT_SPL_SAFETY_ERROR = "spl_safety_error"

# when present, will skip emitting EVENT_TOOL_CALL_COMPLETE because the upstream caller already emitted a more specific telemetry event
TELEMETRY_SUPPRESS_KEY = "_telemetry_suppress"

# Headers that contain sensitive credentials and must be redacted in logs
SENSITIVE_HEADERS: frozenset = frozenset(
    {"authorization", "x-ec-access-token", "x-sf-token"}
)
