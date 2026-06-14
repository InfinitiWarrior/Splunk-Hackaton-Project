import { useState } from "react";

interface Props {
  apiUrl: string;
}

interface SearchResult {
  natural_language: string;
  generated_spl: string;
  result_count: number;
  results: any[];
}

export default function NaturalLanguageSearch({ apiUrl }: Props) {
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState("main");
  const [earliest, setEarliest] = useState("-30d");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SearchResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleSearch() {
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch(`${apiUrl}/splunk/query`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query, index, earliest, latest: "now" }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail ?? `HTTP ${res.status}`);
      }
      const data = await res.json();
      setResult(data);
    } catch (e: any) {
      setError(e.message ?? "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  // Get column headers from first result
  const columns = result?.results?.length
    ? Object.keys(result.results[0]).filter(k => !k.startsWith("_") || k === "_raw" || k === "_time")
    : [];

  const displayColumns = columns.length > 0
    ? columns.filter(c => ["_time", "_raw", "host", "source", "sourcetype", "user", "src_ip", "count"].includes(c))
    : [];

  const finalColumns = displayColumns.length > 0 ? displayColumns : columns.slice(0, 6);

  return (
    <div style={{ maxWidth: 1100, margin: "0 auto" }}>
      <div style={{ marginBottom: 32 }}>
        <h1 style={{ fontSize: 22, fontWeight: 600, color: "var(--text-primary)", marginBottom: 6 }}>
          Natural Language Search
        </h1>
        <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>
          Ask questions in plain English — the AI generates and executes the SPL for you.
        </p>
      </div>

      {/* Search form */}
      <div className="card" style={{ marginBottom: 24 }}>
        <div style={{ display: "flex", gap: 12, marginBottom: 12 }}>
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSearch()}
            placeholder='e.g. "Show me all failed logins in the last hour" or "Who logged in successfully today?"'
            disabled={loading}
            style={{ flex: 1 }}
          />
        </div>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <input
            value={index}
            onChange={(e) => setIndex(e.target.value)}
            placeholder="Index"
            disabled={loading}
            style={{ width: 120 }}
          />
          <input
            value={earliest}
            onChange={(e) => setEarliest(e.target.value)}
            placeholder="Earliest"
            disabled={loading}
            style={{ width: 100 }}
          />
          <button
            onClick={handleSearch}
            disabled={loading || !query.trim()}
            style={{
              background: loading ? "var(--bg-hover)" : "var(--accent)",
              color: loading ? "var(--text-muted)" : "#fff",
              border: "none",
              padding: "8px 20px",
              borderRadius: 6,
              fontSize: 13,
              fontWeight: 600,
              cursor: loading ? "not-allowed" : "pointer",
              transition: "all 0.15s",
            }}
          >
            {loading ? "Thinking..." : "Search →"}
          </button>
        </div>
      </div>

      {/* Example queries */}
      {!result && !loading && (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 24 }}>
          {[
            "Show me all failed login attempts",
            "Who successfully logged in today?",
            "Find all sudo commands run as root",
            "Show SSH activity in the last 2 hours",
            "List all users who logged in from external IPs",
          ].map((example) => (
            <button
              key={example}
              onClick={() => { setQuery(example); }}
              style={{
                background: "var(--bg-card)",
                color: "var(--text-secondary)",
                border: "1px solid var(--border)",
                padding: "6px 12px",
                borderRadius: 6,
                fontSize: 12,
                cursor: "pointer",
                transition: "all 0.15s",
                fontFamily: "Geist Mono",
              }}
              onMouseEnter={e => {
                (e.currentTarget as HTMLButtonElement).style.borderColor = "var(--accent)";
                (e.currentTarget as HTMLButtonElement).style.color = "var(--text-primary)";
              }}
              onMouseLeave={e => {
                (e.currentTarget as HTMLButtonElement).style.borderColor = "var(--border)";
                (e.currentTarget as HTMLButtonElement).style.color = "var(--text-secondary)";
              }}
            >
              {example}
            </button>
          ))}
        </div>
      )}

      {/* Error */}
      {error && (
        <div style={{
          padding: 16, borderRadius: 8, marginBottom: 16,
          background: "rgba(255,77,106,0.05)",
          border: "1px solid rgba(255,77,106,0.3)",
          color: "var(--critical)", fontSize: 13,
        }}>
          ✗ {error}
        </div>
      )}

      {/* Generated SPL */}
      {result && (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div className="card">
            <div className="card-header">Generated SPL</div>
            <div style={{
              fontFamily: "Geist Mono", fontSize: 13,
              color: "var(--accent)",
              padding: "10px 14px",
              background: "var(--bg-hover)",
              borderRadius: 6,
              border: "1px solid var(--border)",
              wordBreak: "break-all",
            }}>
              {result.generated_spl}
            </div>
            <div style={{ marginTop: 8, fontSize: 12, color: "var(--text-muted)" }}>
              {result.result_count} event{result.result_count !== 1 ? "s" : ""} returned
            </div>
          </div>

          {/* Results table */}
          {result.results.length > 0 ? (
            <div className="card">
              <div className="card-header">Results</div>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                  <thead>
                    <tr>
                      {finalColumns.map((col) => (
                        <th key={col} style={{
                          textAlign: "left",
                          padding: "8px 12px",
                          fontFamily: "Geist Mono",
                          fontSize: 11,
                          color: "var(--text-muted)",
                          borderBottom: "1px solid var(--border)",
                          whiteSpace: "nowrap",
                        }}>{col}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {result.results.slice(0, 25).map((row, i) => (
                      <tr key={i} style={{ borderBottom: "1px solid var(--border)" }}
                        onMouseEnter={e => (e.currentTarget.style.background = "var(--bg-hover)")}
                        onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                      >
                        {finalColumns.map((col) => (
                          <td key={col} style={{
                            padding: "8px 12px",
                            color: "var(--text-secondary)",
                            maxWidth: col === "_raw" ? 600 : 200,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: col === "_raw" ? "normal" : "nowrap",
                            fontFamily: col === "_raw" || col === "_time" ? "Geist Mono" : "inherit",
                            fontSize: col === "_raw" ? 11 : 12,
                          }}>
                            {String(row[col] ?? "")}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
                {result.results.length > 25 && (
                  <div style={{ padding: "8px 12px", fontSize: 12, color: "var(--text-muted)", fontFamily: "Geist Mono" }}>
                    Showing 25 of {result.results.length} results
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="card" style={{ color: "var(--text-muted)", fontSize: 13 }}>
              No results found for this query.
            </div>
          )}
        </div>
      )}
    </div>
  );
}