# mcp.conf.spec
# Configuration specification for MCP (Model Context Protocol) server

[server]
* This stanza configures the MCP server settings

timeout = <float>
* Timeout in seconds for requests to Splunk
* Default: 60.0
* Range: 1.0-300.0

max_row_limit = <integer>
* The maximum number of rows that can be returned in a single search query
* Default: 1000
* Range: 1-1000000

default_row_limit = <integer>
* The default maximum number of rows to return in a search query when not specified
* Default: 100
* Range: 1-1000000

ssl_verify = <string|boolean>
* Whether to verify SSL certificates for outgoing HTTPS requests
* Default: true

require_encrypted_token = <boolean>
* Whether bearer tokens must be RSA-encrypted with the server public key.
* If true, non-decryptable tokens are rejected (401). If false, non-decryptable accepted.
* Default: true

[rate_limits]
* This stanza configures request admission controls for /services/mcp.
* `global` is used for tools/call rate limiting.
* `admission_global` controls pre-auth endpoint admission and may be 0 (disabled).
* All values below except `admission_global` must be greater than zero, otherwise requests fail closed (503).

global = <integer>
* Global tools/call requests allowed per 60-second window.
* Default: 600

admission_global = <integer>
* Global pre-auth /services/mcp requests allowed per 60-second window.
* 0 disables this global admission cap.
* Default: 0

tenant_authenticated = <integer>
* Requests allowed per authenticated token per 60-second window.
* Default: 240

tenant_unauthenticated = <integer>
* Requests allowed per source IP (unauthenticated traffic) per 60-second window.
* Default: 60

circuit_breaker_failure_threshold = <integer>
* Consecutive 5xx responses before opening the circuit.
* Default: 20

circuit_breaker_cooldown_seconds = <integer>
* Seconds to keep circuit open before admitting requests again.
* Default: 30
