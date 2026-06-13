// web-frontend/src/components/VelociraptorPanel.tsx
import { useEffect, useState } from "react";

interface Client {
  client_id: string;
  hostname: string;
  last_ip: string;
  os: string;
}

interface StatusData {
  available: boolean;
  client_count: number;
  clients: Client[];
}

interface HuntResult {
  hunt_id?: string;
  artifact?: string;
  available?: boolean;
  client_found?: boolean;
  host?: string;
  artifacts_collected?: string[];
  results?: Record<string, any[]>;
  error?: string;
}

const mono: React.CSSProperties = { fontFamily: "'Geist Mono', monospace" };

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span style={{
      ...mono, display: "inline-block", padding: "2px 8px", borderRadius: 4,
      fontSize: 11, fontWeight: 700, textTransform: "uppercase" as const,
      border: `1px solid ${color}44`, background: `${color}18`, color,
    }}>{label}</span>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 32 }}>
      <div style={{
        ...mono, fontSize: 11, fontWeight: 600, color: "#555",
        textTransform: "uppercase" as const, letterSpacing: "0.1em",
        marginBottom: 14, paddingBottom: 8, borderBottom: "1px solid #2a2a3a",
      }}>{title}</div>
      {children}
    </div>
  );
}

function Card({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <div style={{
      background: "#13131e", border: "1px solid #2a2a3a",
      borderRadius: 8, padding: "14px 16px", ...style,
    }}>
      {children}
    </div>
  );
}

function Input({ label, value, onChange, placeholder }: {
  label: string; value: string; onChange: (v: string) => void; placeholder?: string;
}) {
  return (
    <div style={{ marginBottom: 14 }}>
      <label style={{ ...mono, display: "block", fontSize: 11, color: "#666", textTransform: "uppercase" as const, letterSpacing: "0.06em", marginBottom: 6 }}>
        {label}
      </label>
      <input
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        style={{
          width: "100%", padding: "10px 14px", boxSizing: "border-box" as const,
          background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)",
          borderRadius: 7, ...mono, fontSize: 13, color: "#e0e0f0", outline: "none",
        }}
      />
    </div>
  );
}

const ARTIFACTS = [
  "Linux.Sys.Pslist",
  "Linux.Sys.Users",
  "Linux.Sys.BashHistory",
  "Linux.Sys.Crontab",
  "Linux.Network.Netstat",
  "Linux.Network.NetstatEnriched",
  "Linux.Sys.LastUserLogin",
  "Windows.System.Pslist",
  "Windows.Network.Netstat",
];

export default function VelociraptorPanel({ apiUrl }: { apiUrl: string }) {
  const [status, setStatus] = useState<StatusData | null>(null);
  const [loading, setLoading] = useState(true);
  const [huntHost, setHuntHost] = useState("");
  const [huntArtifact, setHuntArtifact] = useState("Linux.Sys.Pslist");
  const [huntDesc, setHuntDesc] = useState("");
  const [hunting, setHunting] = useState(false);
  const [huntResult, setHuntResult] = useState<HuntResult | null>(null);
  const [huntMsg, setHuntMsg] = useState<{ text: string; ok: boolean } | null>(null);
  const [activeTab, setActiveTab] = useState<"clients" | "hunt">("clients");

  const loadStatus = () => {
    setLoading(true);
    fetch(`${apiUrl}/velociraptor/status`)
      .then(r => r.json())
      .then(d => { setStatus(d); setLoading(false); })
      .catch(() => setLoading(false));
  };

  useEffect(() => { loadStatus(); }, []);

  const runHunt = async () => {
    setHunting(true);
    setHuntResult(null);
    setHuntMsg(null);
    try {
      const body: any = { artifact: huntArtifact, description: huntDesc || "TriagaSOAR manual hunt" };
      if (huntHost) body.host = huntHost;
      const res = await fetch(`${apiUrl}/velociraptor/hunt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      setHuntResult(data);
      if (data.hunt_id || data.client_found === true) {
        setHuntMsg({ text: data.hunt_id ? `Hunt ${data.hunt_id} created` : `Collected ${data.artifacts_collected?.length ?? 0} artifact(s) from ${data.host}`, ok: true });
      } else if (data.client_found === false) {
        setHuntMsg({ text: `No Velociraptor agent found on ${data.host}`, ok: false });
      } else {
        setHuntMsg({ text: data.error ?? "Hunt dispatched", ok: true });
      }
    } catch (e: any) {
      setHuntMsg({ text: e.message, ok: false });
    } finally {
      setHunting(false);
    }
  };

  const msgStyle = (ok: boolean): React.CSSProperties => ({
    ...mono, padding: "10px 14px", borderRadius: 7, fontSize: 13, marginBottom: 14,
    background: ok ? "rgba(6,214,160,0.08)" : "rgba(255,77,106,0.08)",
    border: `1px solid ${ok ? "rgba(6,214,160,0.25)" : "rgba(255,77,106,0.25)"}`,
    color: ok ? "#06d6a0" : "#ff6b6b",
  });

  const btnStyle = (disabled = false): React.CSSProperties => ({
    padding: "10px 20px", borderRadius: 7, cursor: disabled ? "not-allowed" : "pointer",
    border: "1px solid rgba(123,97,255,0.4)", background: "rgba(123,97,255,0.1)",
    color: "#7b61ff", ...mono, fontSize: 13, fontWeight: 600, opacity: disabled ? 0.5 : 1,
  });

  const tabStyle = (active: boolean): React.CSSProperties => ({
    padding: "8px 16px", borderRadius: 6, cursor: "pointer", ...mono,
    fontSize: 12, fontWeight: 600, border: "none",
    background: active ? "rgba(123,97,255,0.15)" : "transparent",
    color: active ? "#7b61ff" : "#555",
  });

  if (loading) return (
    <div style={{ ...mono, color: "#555", fontSize: 13, padding: 32 }}>Connecting to Velociraptor...</div>
  );

  if (!status?.available) return (
    <div style={{ maxWidth: 700, margin: "0 auto", padding: "32px 24px" }}>
      <div style={{ marginBottom: 24 }}>
        <div style={{ ...mono, fontSize: 11, color: "#888", marginBottom: 6, textTransform: "uppercase" as const }}>DFIR Platform</div>
        <h1 style={{ fontSize: 24, fontWeight: 700, margin: "0 0 6px 0" }}>Velociraptor</h1>
      </div>
      <Card>
        <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16 }}>
          <span style={{ fontSize: 24 }}>🦖</span>
          <div>
            <div style={{ fontWeight: 600, marginBottom: 4 }}>Velociraptor not available</div>
            <div style={{ ...mono, fontSize: 12, color: "#555" }}>Set VELOCIRAPTOR_ENABLED=true and restart soc-agent</div>
          </div>
        </div>
        <div style={{ ...mono, fontSize: 12, color: "#555", lineHeight: 1.8 }}>
          <div>1. Run <span style={{ color: "#7b61ff" }}>make up-velociraptor</span></div>
          <div>2. Run <span style={{ color: "#7b61ff" }}>make velociraptor-setup</span></div>
          <div>3. Set <span style={{ color: "#7b61ff" }}>VELOCIRAPTOR_ENABLED=true</span> in .env</div>
          <div>4. Restart soc-agent: <span style={{ color: "#7b61ff" }}>docker restart soc-agent</span></div>
        </div>
      </Card>
    </div>
  );

  return (
    <div style={{ maxWidth: 900, margin: "0 auto", padding: "32px 24px" }}>
      {/* Header */}
      <div style={{ marginBottom: 28, display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <div style={{ ...mono, fontSize: 11, color: "#888", marginBottom: 6, textTransform: "uppercase" as const }}>DFIR Platform</div>
          <h1 style={{ fontSize: 24, fontWeight: 700, margin: "0 0 6px 0" }}>Velociraptor</h1>
          <p style={{ color: "#888", margin: 0, fontSize: 14 }}>Endpoint visibility, artifact collection, and fleet-wide hunting.</p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <Badge label="Connected" color="#06d6a0" />
          <Badge label={`${status.client_count} agents`} color="#7b61ff" />
          <button onClick={loadStatus} style={{ ...btnStyle(), padding: "6px 12px", fontSize: 11 }}>Refresh</button>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 4, marginBottom: 24, borderBottom: "1px solid #2a2a3a", paddingBottom: 8 }}>
        <button style={tabStyle(activeTab === "clients")} onClick={() => setActiveTab("clients")}>Agents</button>
        <button style={tabStyle(activeTab === "hunt")} onClick={() => setActiveTab("hunt")}>Hunt</button>
      </div>

      {/* Clients tab */}
      {activeTab === "clients" && (
        <Section title={`Enrolled Agents (${status.client_count})`}>
          {status.clients.length === 0 ? (
            <Card>
              <div style={{ ...mono, fontSize: 13, color: "#555", textAlign: "center" as const, padding: "24px 0" }}>
                No agents enrolled yet.
                <div style={{ marginTop: 8, fontSize: 12 }}>
                  Deploy a Velociraptor agent to start collecting endpoint telemetry.
                </div>
                <div style={{ marginTop: 12 }}>
                  <a href="https://localhost:8889" target="_blank" style={{ color: "#7b61ff" }}>
                    Open Velociraptor GUI →
                  </a>
                </div>
              </div>
            </Card>
          ) : (
            status.clients.map(c => (
              <Card key={c.client_id} style={{ marginBottom: 8, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 3 }}>{c.hostname || c.client_id}</div>
                  <div style={{ ...mono, fontSize: 11, color: "#555" }}>{c.client_id} · {c.last_ip}</div>
                </div>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <Badge label={c.os || "unknown"} color="#888" />
                  <Badge label="online" color="#06d6a0" />
                </div>
              </Card>
            ))
          )}
        </Section>
      )}

      {/* Hunt tab */}
      {activeTab === "hunt" && (
        <Section title="Dispatch Hunt">
          {huntMsg && <div style={msgStyle(huntMsg.ok)}>{huntMsg.text}</div>}

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 4 }}>
            <Input
              label="Target Host (optional)"
              value={huntHost}
              onChange={setHuntHost}
              placeholder="hostname or IP — leave blank for fleet-wide"
            />
            <div style={{ marginBottom: 14 }}>
              <label style={{ ...mono, display: "block", fontSize: 11, color: "#666", textTransform: "uppercase" as const, letterSpacing: "0.06em", marginBottom: 6 }}>
                Artifact
              </label>
              <select
                value={huntArtifact}
                onChange={e => setHuntArtifact(e.target.value)}
                style={{
                  width: "100%", padding: "10px 14px", boxSizing: "border-box" as const,
                  background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)",
                  borderRadius: 7, ...mono, fontSize: 13, color: "#e0e0f0", outline: "none",
                }}
              >
                {ARTIFACTS.map(a => <option key={a} value={a}>{a}</option>)}
              </select>
            </div>
          </div>
          <Input
            label="Description (optional)"
            value={huntDesc}
            onChange={setHuntDesc}
            placeholder="e.g. Investigating lateral movement from IR-2026-001"
          />

          <button onClick={runHunt} disabled={hunting} style={btnStyle(hunting)}>
            {hunting ? "Dispatching..." : huntHost ? `Hunt ${huntHost}` : "Fleet-wide Hunt"}
          </button>

          {/* Results */}
          {huntResult && (
            <div style={{ marginTop: 20 }}>
              <div style={{ ...mono, fontSize: 11, color: "#555", textTransform: "uppercase" as const, letterSpacing: "0.1em", marginBottom: 10 }}>
                Results
              </div>
              {huntResult.hunt_id && (
                <Card>
                  <div style={{ ...mono, fontSize: 13 }}>
                    <span style={{ color: "#555" }}>Hunt ID: </span>
                    <span style={{ color: "#7b61ff", fontWeight: 600 }}>{huntResult.hunt_id}</span>
                  </div>
                  <div style={{ ...mono, fontSize: 12, color: "#555", marginTop: 6 }}>
                    Fleet-wide hunt dispatched for <span style={{ color: "#e0e0f0" }}>{huntResult.artifact}</span>.
                    View results in the <a href="https://localhost:8889" target="_blank" style={{ color: "#7b61ff" }}>Velociraptor GUI</a>.
                  </div>
                </Card>
              )}
              {huntResult.client_found === true && huntResult.artifacts_collected && (
                <div>
                  <Card style={{ marginBottom: 8 }}>
                    <div style={{ ...mono, fontSize: 12, marginBottom: 8 }}>
                      <span style={{ color: "#555" }}>Host: </span><span style={{ color: "#06d6a0" }}>{huntResult.host}</span>
                      <span style={{ color: "#555", marginLeft: 16 }}>Client: </span><span>{huntResult.client_id}</span>
                    </div>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" as const }}>
                      {huntResult.artifacts_collected.map(a => <Badge key={a} label={a} color="#7b61ff" />)}
                    </div>
                  </Card>
                  {huntResult.results && Object.entries(huntResult.results).map(([artifact, rows]) => (
                    <div key={artifact} style={{ marginBottom: 16 }}>
                      <div style={{ ...mono, fontSize: 11, color: "#7b61ff", marginBottom: 6 }}>{artifact}</div>
                      <div style={{ overflowX: "auto" as const }}>
                        <table style={{ width: "100%", borderCollapse: "collapse" as const, ...mono, fontSize: 11 }}>
                          <thead>
                            <tr>
                              {Object.keys(rows[0] || {}).slice(0, 6).map(k => (
                                <th key={k} style={{ textAlign: "left" as const, padding: "6px 10px", color: "#555", borderBottom: "1px solid #2a2a3a" }}>{k}</th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {rows.slice(0, 10).map((row, i) => (
                              <tr key={i} style={{ borderBottom: "1px solid #1a1a2a" }}>
                                {Object.values(row).slice(0, 6).map((v: any, j) => (
                                  <td key={j} style={{ padding: "6px 10px", color: "#aaa", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" as const }}>
                                    {String(v ?? "")}
                                  </td>
                                ))}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                        {rows.length > 10 && <div style={{ ...mono, fontSize: 11, color: "#555", padding: "6px 10px" }}>+{rows.length - 10} more rows</div>}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </Section>
      )}
    </div>
  );
}