from fastapi import FastAPI, HTTPException, BackgroundTasks
from velociraptor import hunt_host, get_clients, create_hunt, velo_available
from fastapi.responses import StreamingResponse, JSONResponse, Response
from contextlib import asynccontextmanager
import asyncio
import os
import re
import json
import tempfile
import httpx
from datetime import datetime, timezone
from splunk_mcp import run_query, call_tool
from agent import triage, ollama_chat
from report import generate_ir_report
from database import init_db, save_report, correlate, get_all_cases, get_case, get_connection, set_verdict, get_stats, get_playbook_executions
from playbooks import run_playbooks, load_playbooks
from blast_radius import estimate_blast_radius
from streaming import stream_investigation
from webhook import parse_splunk_webhook
from monitor import monitor_loop, get_saved_alerts, MONITOR_INTERVAL
from threat_intel import enrich_ips, lookup_ip
from patterns import PATTERNS
from entra import (
    entra_available, get_signin_logs, get_failed_signins, get_risky_users,
    get_risk_detections, get_security_alerts, get_audit_logs, get_user,
    get_user_by_ip, disable_user, revoke_sessions, enable_user,
    enrich_user_from_entra, enrich_users_from_entra,
)

monitor_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global monitor_task
    init_db()
    if os.getenv("MONITOR_ENABLED", "false").lower() == "true":
        monitor_task = asyncio.create_task(monitor_loop(app))
        print("[monitor] Monitor started")
    yield
    if monitor_task:
        monitor_task.cancel()


app = FastAPI(title="SOC Triage Agent", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/test/splunk")
async def test_splunk():
    results = await run_query("index=* | head 5")
    return {"count": len(results), "sample": results[0] if results else None}


@app.post("/triage")
async def triage_alert(alert: dict):
    return await triage(alert)


@app.post("/investigate")
async def investigate_alert(alert: dict):
    prior_cases = correlate(alert)
    result = await triage(alert)
    report = generate_ir_report(alert, result)
    blast = await estimate_blast_radius(alert, report)
    report["blast_radius"] = blast
    attacker_ips = blast.get("attacker_ips", [])
    report["threat_intel"] = await enrich_ips(attacker_ips) if attacker_ips else {}
    if prior_cases:
        report["prior_cases"] = prior_cases
        report["repeated_attacker"] = True
    else:
        report["prior_cases"] = []
        report["repeated_attacker"] = False
    case_id = save_report(report, alert)
    report["case_id"] = case_id
    # Run playbooks against the completed report
    conn = get_connection()
    report["playbook_executions"] = await run_playbooks(report, db_conn=conn)
    conn.close()
    return report


@app.post("/investigate/stream")
async def investigate_stream(alert: dict):
    return StreamingResponse(
        stream_investigation(alert),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/webhook")
async def splunk_webhook(payload: dict, background_tasks: BackgroundTasks):
    alert = parse_splunk_webhook(payload)
    if not alert:
        raise HTTPException(status_code=400, detail="Could not parse webhook payload")
    background_tasks.add_task(run_webhook_investigation, alert)
    return {
        "status": "accepted",
        "alert_title": alert["title"],
        "search_terms": alert["search_terms"],
    }


async def run_webhook_investigation(alert: dict):
    try:
        prior_cases = correlate(alert)
        result = await triage(alert)
        report = generate_ir_report(alert, result)
        blast = await estimate_blast_radius(alert, report)
        report["blast_radius"] = blast
        attacker_ips = blast.get("attacker_ips", [])
        report["threat_intel"] = await enrich_ips(attacker_ips) if attacker_ips else {}
        report["prior_cases"] = prior_cases
        report["repeated_attacker"] = len(prior_cases) > 0
        report["triggered_by"] = "webhook"
        case_id = save_report(report, alert)
        report["case_id"] = case_id
        conn = get_connection()
        await run_playbooks(report, db_conn=conn)
        conn.close()
    except Exception as e:
        print(f"Webhook investigation failed: {e}")


@app.get("/monitor/status")
async def monitor_status():
    return {
        "enabled": monitor_task is not None and not monitor_task.done(),
        "interval_seconds": MONITOR_INTERVAL,
    }


@app.get("/monitor/alerts")
async def list_monitor_alerts():
    alerts = await get_saved_alerts()
    return {"count": len(alerts), "alerts": alerts}


@app.get("/threatintel/{ip}")
async def threat_intel_lookup(ip: str):
    return await lookup_ip(ip)


# ── NL→SPL sanitization ───────────────────────────────────────────────────────

_INJECTION_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"ignore\s+(previous|above|all)\s+instructions?",
        r"system\s*:",
        r"assistant\s*:",
        r"<\s*/?think\s*>",
        r"index\s*=",
        r"\|\s*eval\s+",
        r"\|\s*exec\s*\(",
        r"\\n",
        r"```",
    ]
]

def sanitize_nl_query(query: str) -> str:
    query = query[:500].strip()
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(query):
            raise ValueError(f"Query contains disallowed pattern")
    if any(ord(c) < 32 and c not in ('\t',) for c in query):
        raise ValueError("Query contains control characters")
    return query

def validate_spl_output(spl: str, expected_index: str) -> str:
    spl = spl.strip()
    if not spl.startswith(f"index={expected_index}"):
        raise ValueError(f"SPL must start with index={expected_index}, got: {spl[:60]}")
    for pattern in [r"\|\s*exec\b", r"\|\s*script\b", r"\|\s*runshellscript\b",
                    r"\|\s*sendemail\b", r"\|\s*outputlookup\b", r"\|\s*collect\b"]:
        if re.search(pattern, spl, re.IGNORECASE):
            raise ValueError(f"SPL contains dangerous command")
    if len(spl) > 1000:
        raise ValueError("Generated SPL exceeds maximum length")
    return spl


@app.post("/splunk/query")
async def natural_language_query(body: dict):
    raw_query = body.get("query", "")
    index = body.get("index", "main")
    earliest = body.get("earliest", "-1h")
    latest = body.get("latest", "now")

    if not raw_query:
        raise HTTPException(status_code=400, detail="Query is required")

    if not re.match(r'^[a-zA-Z0-9_\-]+$', index):
        raise HTTPException(status_code=400, detail="Invalid index name")

    try:
        nl_query = sanitize_nl_query(raw_query)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid query: {e}")

    # User input isolated in separate message — not interpolated into system prompt
    messages = [
        {
            "role": "system",
            "content": (
                f"You are a Splunk SPL expert. Convert natural language queries to valid SPL.\n"
                f"Rules:\n"
                f"- Always start with: index={index}\n"
                f"- Available index: {index}\n"
                f"- Sourcetype available: linux_secure (raw syslog auth logs)\n"
                f"- Use raw text search with quotes since fields are not extracted\n"
                f"- Keep it simple and functional\n"
                f"- Return ONLY the SPL query, nothing else, no explanation, no markdown, no code fences\n"
                f"- Never use exec, script, runshellscript, sendemail, outputlookup, or collect commands"
            )
        },
        {
            "role": "user",
            "content": nl_query
        }
    ]

    result = await ollama_chat(os.getenv("REASONER_MODEL", "qwen3:14b"), messages)
    spl = result["message"]["content"].strip()

    if "<think>" in spl:
        spl = spl[spl.rfind("</think>") + 8:].strip()
    if "```" in spl:
        lines = spl.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        spl = "\n".join(lines).strip()

    try:
        spl = validate_spl_output(spl, index)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=f"Generated invalid SPL: {e}")

    results = await run_query(spl, earliest=earliest, latest=latest, limit=50)
    return {
        "natural_language": nl_query,
        "generated_spl": spl,
        "result_count": len(results),
        "results": results,
    }


@app.get("/splunk/health")
async def splunk_health():
    info_task = call_tool("splunk_get_info", {})
    indexes_task = call_tool("splunk_get_indexes", {"row_limit": 50})
    metadata_task = call_tool("splunk_get_metadata", {"type": "sourcetypes", "index": "*"})

    info_result, indexes_result, metadata_result = await asyncio.gather(
        info_task, indexes_task, metadata_task, return_exceptions=True
    )

    instance_info = {}
    if not isinstance(info_result, Exception):
        content = info_result.get("result", {}).get("structuredContent", {})
        results = content.get("results", [])
        if results:
            instance_info = results[0]

    indexes = []
    if not isinstance(indexes_result, Exception):
        content = indexes_result.get("result", {}).get("structuredContent", {})
        indexes = content.get("results", [])

    sourcetypes = []
    if not isinstance(metadata_result, Exception):
        content = metadata_result.get("result", {}).get("structuredContent", {})
        sourcetypes = content.get("results", [])

    return {"instance": instance_info, "indexes": indexes, "sourcetypes": sourcetypes}


@app.get("/attackers/{ip}")
async def attacker_profile(ip: str):
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT c.report_id, c.created_at, c.title, c.severity,
                   c.alert_type, c.confidence, c.kill_chain, c.full_report
            FROM cases c
            JOIN entities e ON e.case_id = c.id
            WHERE e.type = 'ip' AND e.value = ?
            ORDER BY c.created_at ASC
        """, (ip,)).fetchall()

        if not rows:
            raise HTTPException(status_code=404, detail=f"No cases found for IP {ip}")

        cases = []
        all_techniques = {}
        all_users = set()
        total_events = 0

        for row in rows:
            report = json.loads(row["full_report"])
            blast = report.get("blast_radius", {})
            total_events += sum(
                int(e.get("event_count", 0) or 0)
                for e in blast.get("related_events", [])
                if e.get("entity") == ip
            )
            for u in blast.get("compromised_users", []):
                all_users.add(u)
            for t in report.get("mitre_techniques", []):
                tid = t["technique_id"]
                if tid not in all_techniques:
                    all_techniques[tid] = {**t, "count": 0}
                all_techniques[tid]["count"] += 1
            cases.append({
                "report_id": row["report_id"],
                "created_at": row["created_at"],
                "title": row["title"],
                "severity": row["severity"],
                "alert_type": row["alert_type"],
                "confidence": row["confidence"],
                "kill_chain": row["kill_chain"],
            })

        return {
            "ip": ip,
            "first_seen": cases[0]["created_at"],
            "last_seen": cases[-1]["created_at"],
            "total_incidents": len(cases),
            "total_events": total_events,
            "compromised_users": list(all_users),
            "techniques": sorted(all_techniques.values(), key=lambda t: t["count"], reverse=True),
            "cases": cases,
        }
    finally:
        conn.close()


@app.get("/patterns")
async def list_patterns():
    return PATTERNS


@app.get("/patterns/{pattern_id}")
async def get_pattern(pattern_id: str):
    pattern = next((p for p in PATTERNS if p["id"] == pattern_id), None)
    if not pattern:
        raise HTTPException(status_code=404, detail="Pattern not found")
    return pattern


@app.patch("/cases/{report_id}/verdict")
async def update_verdict(report_id: str, body: dict):
    verdict = body.get("verdict")
    if verdict not in ("confirmed", "false_positive", None):
        raise HTTPException(status_code=400, detail="verdict must be 'confirmed', 'false_positive', or null")
    success = set_verdict(report_id, verdict)
    if not success:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"report_id": report_id, "verdict": verdict}


@app.get("/stats")
async def statistics():
    return get_stats()


@app.get("/cases/compare")
async def compare_cases(a: str, b: str):
    case_a = get_case(a)
    case_b = get_case(b)
    if not case_a:
        raise HTTPException(status_code=404, detail=f"Case {a} not found")
    if not case_b:
        raise HTTPException(status_code=404, detail=f"Case {b} not found")

    techs_a = {t["technique_id"] for t in case_a.get("mitre_techniques", [])}
    techs_b = {t["technique_id"] for t in case_b.get("mitre_techniques", [])}

    return {
        "case_a": {
            "report_id": case_a.get("report_id"),
            "title": case_a.get("alert", {}).get("title"),
            "severity": case_a.get("severity"),
            "confidence": case_a.get("final_confidence"),
            "summary": case_a.get("summary"),
            "mitre_techniques": case_a.get("mitre_techniques", []),
            "kill_chain": case_a.get("kill_chain_summary"),
            "findings_count": len(case_a.get("findings", [])),
            "blast_radius": case_a.get("blast_radius", {}),
            "adversarial_review": case_a.get("adversarial_review", {}),
            "generated_at": case_a.get("generated_at"),
            "verdict": case_a.get("verdict"),
        },
        "case_b": {
            "report_id": case_b.get("report_id"),
            "title": case_b.get("alert", {}).get("title"),
            "severity": case_b.get("severity"),
            "confidence": case_b.get("final_confidence"),
            "summary": case_b.get("summary"),
            "mitre_techniques": case_b.get("mitre_techniques", []),
            "kill_chain": case_b.get("kill_chain_summary"),
            "findings_count": len(case_b.get("findings", [])),
            "blast_radius": case_b.get("blast_radius", {}),
            "adversarial_review": case_b.get("adversarial_review", {}),
            "generated_at": case_b.get("generated_at"),
            "verdict": case_b.get("verdict"),
        },
        "diff": {
            "techniques_only_in_a": list(techs_a - techs_b),
            "techniques_only_in_b": list(techs_b - techs_a),
            "techniques_in_both": list(techs_a & techs_b),
            "severity_match": case_a.get("severity") == case_b.get("severity"),
            "confidence_delta": round(
                (case_a.get("final_confidence", 0) - case_b.get("final_confidence", 0)) * 100, 1
            ),
        },
    }


@app.post("/splunk/saved-searches")
async def create_saved_search(body: dict):
    name = body.get("name", "")
    spl = body.get("spl", "")
    description = body.get("description", "")

    if not name or not spl:
        raise HTTPException(status_code=400, detail="name and spl are required")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    unique_name = f"{name} [{ts}]"

    splunk_host = os.getenv("SPLUNK_HOST", "localhost")
    splunk_port = os.getenv("SPLUNK_PORT", "8089")
    splunk_token = os.getenv("SPLUNK_WRITE_TOKEN") or os.getenv("SPLUNK_TOKEN", "")

    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            response = await client.post(
                f"https://{splunk_host}:{splunk_port}/servicesNS/nobody/search/saved/searches",
                headers={"Authorization": f"Bearer {splunk_token}"},
                data={"name": unique_name, "search": spl, "description": description},
            )
            if response.status_code not in (200, 201):
                raise HTTPException(status_code=502, detail=f"Splunk returned {response.status_code}: {response.text[:300]}")
            return {"status": "created", "name": unique_name}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create saved search: {str(e)}")


@app.get("/cases/{report_id}/navigator")
async def mitre_navigator_export(report_id: str):
    case = get_case(report_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    techniques = case.get("mitre_techniques", [])
    confidence = case.get("final_confidence", 0)

    layer = {
        "name": f"SOC Triage — {case.get('alert', {}).get('title', report_id)}",
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Auto-generated by Splunk SOC Triage Agent. Report: {report_id}. Confidence: {round(confidence * 100)}%",
        "filters": {"platforms": ["Linux", "Windows", "macOS"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "average", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": [],
        "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 100},
        "legendItems": [{"label": "Detected technique", "color": "#ff6666"}],
        "metadata": [], "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#16161f",
        "selectTechniquesAcrossTactics": False,
        "selectSubtechniquesWithParent": False,
    }

    for t in techniques:
        layer["techniques"].append({
            "techniqueID": t.get("technique_id", ""),
            "tactic": t.get("tactic", "").lower().replace(" ", "-"),
            "score": round(confidence * 100),
            "color": "",
            "comment": t.get("technique_name", ""),
            "enabled": True,
            "metadata": [], "links": [],
            "showSubtechniques": True,
        })

    return JSONResponse(
        content=layer,
        headers={"Content-Disposition": f"attachment; filename=navigator_{report_id}.json", "Content-Type": "application/json"}
    )


@app.get("/cases/{report_id}/pdf")
async def export_pdf(report_id: str):
    from weasyprint import HTML

    case = get_case(report_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    confidence = case.get("final_confidence", 0)
    severity = case.get("severity", "unknown")
    alert = case.get("alert", {})
    findings = case.get("findings", [])
    mitre = case.get("mitre_techniques", [])
    blast = case.get("blast_radius", {})
    recommendations = case.get("recommendations", [])
    review = case.get("adversarial_review", {})
    queries = case.get("queries_run", [])
    threat_intel = case.get("threat_intel", {})

    severity_colors = {"critical": "#ff4d6a", "high": "#ff8c42", "medium": "#ffd166", "low": "#06d6a0"}
    color = severity_colors.get(severity, "#7c7c7c")

    kill_chain_html = ""
    if mitre:
        techs = " → ".join(
            f'<span style="color:#7b61ff;font-family:monospace">{t["technique_id"]}</span> <span style="color:#ccc">{t["technique_name"]}</span>'
            for t in mitre
        )
        kill_chain_html = f'<div style="margin-bottom:8px">{techs}</div>'

    findings_html = "".join(f"""
        <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #2a2a3a">
            <span style="color:#c0c0d0;flex:1">{f.get('finding','')}</span>
            <span style="color:#ff8c42;font-family:monospace;margin-left:16px">{round(f.get('confidence',0)*100)}%</span>
        </div>
    """ for f in findings)

    blast_ips = ", ".join(blast.get("attacker_ips", [])) or "None"
    blast_users = ", ".join(blast.get("compromised_users", [])) or "None"
    blast_hosts = ", ".join(blast.get("affected_hosts", [])) or "None"
    recommendations_html = "".join(f'<div style="padding:4px 0;color:#c0c0d0">→ {r}</div>' for r in recommendations)
    queries_html = "".join(f'<div style="font-family:monospace;font-size:11px;color:#7b61ff;padding:4px 8px;background:#16161f;border-radius:4px;margin-bottom:4px">{q}</div>' for q in queries)

    threat_html = ""
    for ip, intel in threat_intel.items():
        if intel.get("available"):
            threat_html += f'<div style="padding:8px;background:#16161f;border-radius:6px;margin-bottom:8px"><span style="font-family:monospace;color:#ff4d6a">{ip}</span><span style="margin-left:12px;color:#888">Abuse: {intel.get("abuse_confidence_score")}% · {intel.get("country_code")} · {intel.get("isp")} · {intel.get("threat_level","").upper()}</span></div>'
        else:
            threat_html += f'<div style="padding:8px;background:#16161f;border-radius:6px;margin-bottom:8px"><span style="font-family:monospace;color:#ff4d6a">{ip}</span><span style="margin-left:12px;color:#888">{intel.get("message","")}</span></div>'

    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>
        body {{ font-family: -apple-system, sans-serif; background: #0d0d14; color: #e0e0f0; margin: 0; padding: 40px; }}
        h1 {{ font-size: 22px; font-weight: 700; margin: 0 0 4px 0; }}
        h2 {{ font-size: 13px; font-weight: 600; color: #888; letter-spacing: 0.08em; text-transform: uppercase; margin: 0 0 12px 0; border-bottom: 1px solid #2a2a3a; padding-bottom: 6px; }}
        .card {{ background: #13131e; border: 1px solid #2a2a3a; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; border: 1px solid {color}44; background: {color}22; color: {color}; }}
        .meta {{ font-size: 12px; color: #888; margin-top: 4px; }}
        .confidence {{ font-family: monospace; font-size: 36px; font-weight: 700; color: {color}; }}
    </style></head><body>
    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:32px">
        <div>
            <div style="font-family:monospace;font-size:11px;color:#888;margin-bottom:6px">SOC TRIAGE · {case.get('report_id','')}</div>
            <h1>{alert.get('title','Unknown Alert')}</h1>
            <div class="meta">{alert.get('index','')} · {alert.get('time_range','')} · {case.get('generated_at','')}</div>
            <div style="margin-top:10px"><span class="badge">{severity}</span></div>
        </div>
        <div style="text-align:right">
            <div class="confidence">{round(confidence*100)}%</div>
            <div style="font-size:11px;color:#888">confidence</div>
        </div>
    </div>
    <div class="card"><h2>Summary</h2><p style="color:#c0c0d0;line-height:1.7;margin:0">{case.get('summary','')}</p></div>
    <div class="card"><h2>MITRE ATT&amp;CK Kill Chain</h2>{kill_chain_html if kill_chain_html else '<span style="color:#888">No techniques mapped</span>'}</div>
    <div class="card"><h2>Investigation Findings</h2>{findings_html if findings_html else '<span style="color:#888">No findings</span>'}</div>
    <div class="card"><h2>Blast Radius</h2>
        <div style="color:#c0c0d0;margin-bottom:10px">{blast.get('risk_summary','')}</div>
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px">
            <div><div style="font-size:10px;color:#888;font-family:monospace;margin-bottom:4px">ATTACKER IPS</div><div style="color:#ff4d6a;font-family:monospace">{blast_ips}</div></div>
            <div><div style="font-size:10px;color:#888;font-family:monospace;margin-bottom:4px">COMPROMISED USERS</div><div style="color:#ff8c42;font-family:monospace">{blast_users}</div></div>
            <div><div style="font-size:10px;color:#888;font-family:monospace;margin-bottom:4px">AFFECTED HOSTS</div><div style="color:#ffd166;font-family:monospace">{blast_hosts}</div></div>
        </div>
    </div>
    {f'<div class="card"><h2>Threat Intelligence</h2>{threat_html}</div>' if threat_html else ''}
    <div class="card"><h2>Adversarial Review</h2>
        <div style="margin-bottom:8px"><span style="font-family:monospace;font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px;background:{'rgba(6,214,160,0.1)' if review.get('verdict')=='approved' else 'rgba(255,209,102,0.1)'};color:{'#06d6a0' if review.get('verdict')=='approved' else '#ffd166'};border:1px solid {'rgba(6,214,160,0.3)' if review.get('verdict')=='approved' else 'rgba(255,209,102,0.3)'};text-transform:uppercase">{review.get('verdict','')}</span></div>
        <p style="color:#c0c0d0;line-height:1.7;margin:0">{review.get('critique','')}</p>
    </div>
    <div class="card"><h2>Recommendations</h2>{recommendations_html if recommendations_html else '<span style="color:#888">None</span>'}</div>
    <div class="card"><h2>SPL Queries Executed</h2>{queries_html if queries_html else '<span style="color:#888">None</span>'}</div>
    <div style="text-align:center;color:#444;font-size:11px;margin-top:32px;font-family:monospace">Generated by Splunk SOC Triage Agent · {case.get('report_id','')}</div>
    </body></html>"""

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        HTML(string=html).write_pdf(f.name)
        pdf_path = f.name

    with open(pdf_path, "rb") as f:
        pdf_bytes = f.read()

    os.unlink(pdf_path)
    return Response(content=pdf_bytes, media_type="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename=IR_{report_id}.pdf"})


@app.get("/cases")
async def list_cases():
    return get_all_cases()


@app.get("/cases/{report_id}")
async def get_case_by_id(report_id: str):
    case = get_case(report_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


# ── Cross-platform identity correlation ───────────────────────────────────────

@app.get("/identity/correlate")
async def correlate_identity(email: str = None, upn: str = None):
    """
    Given an email or UPN, find matching accounts across all configured IDPs
    (Entra ID, Okta, Auth0) and return a unified identity view.
    """
    if not email and not upn:
        raise HTTPException(status_code=400, detail="email or upn required")

    search_email = email or upn
    # Normalise — strip domain variations, lowercase
    search_email = search_email.lower().strip()

    results = {
        "search": search_email,
        "entra": None,
        "okta": None,
        "auth0": None,
        "correlation_confidence": 0.0,
        "risk_summary": [],
    }

    tasks = []

    # Entra ID lookup
    async def lookup_entra():
        if not entra_available():
            return
        try:
            data = await enrich_user_from_entra(search_email)
            if data.get("available"):
                results["entra"] = {
                    "id": data.get("id"),
                    "upn": data.get("userPrincipalName"),
                    "display_name": data.get("displayName"),
                    "email": data.get("mail") or data.get("userPrincipalName"),
                    "risk_level": data.get("risk_level"),
                    "risk_state": data.get("risk_state"),
                    "account_enabled": data.get("accountEnabled"),
                    "signin_count_48h": data.get("signin_count_48h"),
                    "failed_signin_count_48h": data.get("failed_signin_count_48h"),
                }
        except Exception:
            pass

    # Okta lookup
    async def lookup_okta():
        try:
            from okta import okta_available, get_users, enrich_user_from_okta
            if not okta_available():
                return
            # Use Okta filter syntax for exact email match
            users = await get_users(limit=5, search=f'profile.email eq "{search_email}" or profile.login eq "{search_email}"')
            match = next((u for u in users if
                (u.get("profile", {}).get("email", "").lower() == search_email or
                 u.get("profile", {}).get("login", "").lower() == search_email)), None)
            if not match:
                # Fallback: fetch all and filter client-side
                all_users = await get_users(limit=50)
                match = next((u for u in all_users if
                    (u.get("profile", {}).get("email", "").lower() == search_email or
                     u.get("profile", {}).get("login", "").lower() == search_email)), None)
            if match:
                detail = await enrich_user_from_okta(match["id"])
                results["okta"] = {
                    "id": match.get("id"),
                    "login": match.get("profile", {}).get("login"),
                    "email": match.get("profile", {}).get("email"),
                    "display_name": f"{match.get('profile',{}).get('firstName','')} {match.get('profile',{}).get('lastName','')}".strip(),
                    "status": match.get("status"),
                    "signin_count_48h": detail.get("signin_count_48h"),
                    "failed_signin_count_48h": detail.get("failed_signin_count_48h"),
                    "recent_ips": detail.get("recent_ips", []),
                }
        except Exception as e:
            print(f"[correlation] Okta lookup failed: {e}")

    # Auth0 lookup
    async def lookup_auth0():
        try:
            from auth0 import auth0_available, get_users, enrich_user_from_auth0
            if not auth0_available():
                return
            users = await get_users(per_page=5, q=f'email:"{search_email}"')
            match = next((u for u in users if u.get("email", "").lower() == search_email), None)
            if match:
                detail = await enrich_user_from_auth0(match["user_id"])
                results["auth0"] = {
                    "id": match.get("user_id"),
                    "email": match.get("email"),
                    "name": match.get("name"),
                    "blocked": match.get("blocked", False),
                    "logins_count": match.get("logins_count", 0),
                    "last_login": match.get("last_login"),
                    "last_ip": match.get("last_ip"),
                    "failed_signin_count_48h": detail.get("failed_signin_count_48h"),
                    "recent_ips": detail.get("recent_ips", []),
                }
        except Exception as e:
            print(f"[correlation] Auth0 lookup failed: {e}")

    await asyncio.gather(lookup_entra(), lookup_okta(), lookup_auth0())

    # Compute correlation confidence and risk summary
    found_in = sum(1 for v in [results["entra"], results["okta"], results["auth0"]] if v)
    results["correlation_confidence"] = round(found_in / 3, 2)
    results["found_in"] = [k for k in ["entra", "okta", "auth0"] if results[k]]

    # Aggregate risk signals
    risk_signals = []
    if results["entra"]:
        if results["entra"].get("risk_level") in ("high", "medium"):
            risk_signals.append(f"Entra ID: {results['entra']['risk_level']} risk ({results['entra'].get('risk_state')})")
        if not results["entra"].get("account_enabled"):
            risk_signals.append("Entra ID: account disabled")
        if (results["entra"].get("failed_signin_count_48h") or 0) > 5:
            risk_signals.append(f"Entra ID: {results['entra']['failed_signin_count_48h']} failed sign-ins in 48h")

    if results["okta"]:
        if results["okta"].get("status") in ("SUSPENDED", "LOCKED_OUT"):
            risk_signals.append(f"Okta: account {results['okta']['status'].lower()}")
        if (results["okta"].get("failed_signin_count_48h") or 0) > 5:
            risk_signals.append(f"Okta: {results['okta']['failed_signin_count_48h']} failed sign-ins in 48h")

    if results["auth0"]:
        if results["auth0"].get("blocked"):
            risk_signals.append("Auth0: user blocked")
        if (results["auth0"].get("failed_signin_count_48h") or 0) > 5:
            risk_signals.append(f"Auth0: {results['auth0']['failed_signin_count_48h']} failed sign-ins in 48h")

    # Cross-IDP IP correlation — flag if same suspicious IP appears in multiple IDPs
    all_ips = set()
    shared_ips = set()
    for idp in ["okta", "auth0"]:
        if results[idp]:
            ips = set(results[idp].get("recent_ips", []))
            shared_ips |= all_ips & ips
            all_ips |= ips
    if shared_ips:
        risk_signals.append(f"Cross-IDP: shared suspicious IPs {', '.join(list(shared_ips)[:3])}")

    results["risk_summary"] = risk_signals
    results["overall_risk"] = "high" if len(risk_signals) >= 3 else "medium" if len(risk_signals) >= 1 else "low"

    return results


@app.get("/identity/search")
async def search_identity(q: str):
    """Search for a user across all IDPs simultaneously."""
    if not q or len(q) < 3:
        raise HTTPException(status_code=400, detail="Search query must be at least 3 characters")
    return await correlate_identity(email=q)


# ── Playbook endpoints ────────────────────────────────────────────────────────

@app.get("/playbooks")
async def list_playbooks():
    """List all playbooks with their conditions and enabled state."""
    playbooks = load_playbooks()
    return {
        "count": len(playbooks),
        "playbooks": [
            {
                "id": pb.get("id"),
                "name": pb.get("name"),
                "description": pb.get("description", "").strip(),
                "enabled": pb.get("enabled", True),
                "conditions": pb.get("conditions", {}),
                "action_count": len(pb.get("actions", [])),
                "action_types": [a.get("type") for a in pb.get("actions", [])],
            }
            for pb in playbooks
        ]
    }


@app.get("/playbooks/executions")
async def playbook_executions(limit: int = 50):
    """Recent playbook execution history."""
    return {"executions": get_playbook_executions(limit=limit)}


@app.get("/playbooks/executions/{report_id}")
async def playbook_executions_for_case(report_id: str):
    """Playbook executions for a specific case."""
    return {"executions": get_playbook_executions(report_id=report_id)}


@app.post("/playbooks/test/{playbook_id}")
async def test_playbook(playbook_id: str, report: dict):
    """Dry-run: evaluate conditions only, do not execute actions."""
    from playbooks import evaluate_conditions, build_context
    playbooks = load_playbooks()
    pb = next((p for p in playbooks if p["id"] == playbook_id), None)
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found")
    matched = evaluate_conditions(pb.get("conditions", {}), report)
    ctx = build_context(report)
    return {
        "playbook_id": playbook_id,
        "matched": matched,
        "conditions": pb.get("conditions", {}),
        "context": ctx,
    }


# ── Entra ID endpoints ────────────────────────────────────────────────────────

@app.get("/entra/health")
async def entra_health():
    if not entra_available():
        return {"available": False, "message": "ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET not set"}
    try:
        from entra import get_token
        await get_token()
        return {"available": True, "tenant_id": os.getenv("ENTRA_TENANT_ID")}
    except Exception as e:
        return {"available": False, "message": str(e)}


@app.get("/entra/signins")
async def entra_signins(hours: int = 24, top: int = 50, user: str = None, ip: str = None):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    return {"signins": await get_signin_logs(hours=hours, top=top, user_upn=user, ip=ip)}


@app.get("/entra/signins/failed")
async def entra_failed_signins(hours: int = 24, top: int = 50):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    logs = await get_failed_signins(hours=hours, top=top)
    return {"count": len(logs), "signins": logs}


@app.get("/entra/risky-users")
async def entra_risky_users(risk_level: str = None):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    users = await get_risky_users(risk_level=risk_level)
    return {"count": len(users), "users": users}


@app.get("/entra/risk-detections")
async def entra_risk_detections(hours: int = 48, top: int = 50):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    detections = await get_risk_detections(hours=hours, top=top)
    return {"count": len(detections), "detections": detections}


@app.get("/entra/alerts")
async def entra_security_alerts(hours: int = 48, top: int = 50, severity: str = None):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    alerts = await get_security_alerts(hours=hours, top=top, severity=severity)
    return {"count": len(alerts), "alerts": alerts}


@app.get("/entra/audit-logs")
async def entra_audit_logs(hours: int = 24, top: int = 50, category: str = None):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    logs = await get_audit_logs(hours=hours, top=top, category=category)
    return {"count": len(logs), "logs": logs}


@app.get("/entra/users/{upn_or_id}")
async def entra_user(upn_or_id: str):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    return await enrich_user_from_entra(upn_or_id)


@app.get("/entra/users/by-ip/{ip}")
async def entra_users_by_ip(ip: str, hours: int = 24):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    users = await get_user_by_ip(ip=ip, hours=hours)
    return {"ip": ip, "users": users}


@app.post("/entra/actions/disable-user")
async def entra_disable_user(body: dict):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    user_id = body.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="user_id required")
    result = await disable_user(user_id)
    conn = get_connection()
    conn.execute("INSERT INTO response_actions (action, target, performed_at, details, provider) VALUES (?,?,?,?,?)",
        ("disable_user", user_id, datetime.now(timezone.utc).isoformat(), json.dumps(result), "entra"))
    conn.commit(); conn.close()
    return result


@app.post("/entra/actions/revoke-sessions")
async def entra_revoke_sessions(body: dict):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    user_id = body.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="user_id required")
    result = await revoke_sessions(user_id)
    conn = get_connection()
    conn.execute("INSERT INTO response_actions (action, target, performed_at, details, provider) VALUES (?,?,?,?,?)",
        ("revoke_sessions", user_id, datetime.now(timezone.utc).isoformat(), json.dumps(result), "entra"))
    conn.commit(); conn.close()
    return result


@app.post("/entra/actions/enable-user")
async def entra_enable_user(body: dict):
    if not entra_available():
        raise HTTPException(status_code=503, detail="Entra ID not configured")
    user_id = body.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="user_id required")
    result = await enable_user(user_id)
    conn = get_connection()
    conn.execute("INSERT INTO response_actions (action, target, performed_at, details, provider) VALUES (?,?,?,?,?)",
        ("enable_user", user_id, datetime.now(timezone.utc).isoformat(), json.dumps(result), "entra"))
    conn.commit(); conn.close()
    return result



@app.get("/okta/actions")
async def okta_action_log():
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM response_actions WHERE provider = 'okta' ORDER BY performed_at DESC LIMIT 100").fetchall()
        return {"actions": [dict(r) for r in rows]}
    finally:
        conn.close()

@app.get("/auth0/actions")
async def auth0_action_log():
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM response_actions WHERE provider = 'auth0' ORDER BY performed_at DESC LIMIT 100").fetchall()
        return {"actions": [dict(r) for r in rows]}
    finally:
        conn.close()
@app.get("/entra/actions")
async def entra_action_log():
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM response_actions WHERE provider = 'entra' ORDER BY performed_at DESC LIMIT 100").fetchall()
        return {"actions": [dict(r) for r in rows]}
    finally:
        conn.close()


# ── Maester endpoints ─────────────────────────────────────────────────────────

MAESTER_OUTPUT_DIR = os.getenv("MAESTER_OUTPUT_DIR", "/app/data/maester")

def _read_maester_latest() -> dict | None:
    path = os.path.join(MAESTER_OUTPUT_DIR, "latest.json")
    if not os.path.exists(path): return None
    with open(path) as f: return json.load(f)

def _read_maester_status() -> dict | None:
    path = os.path.join(MAESTER_OUTPUT_DIR, "status.json")
    if not os.path.exists(path): return None
    with open(path) as f: return json.load(f)


@app.get("/maester/status")
async def maester_status():
    status = _read_maester_status()
    if not status:
        return {"available": False, "message": "No Maester output found. Run the maester container."}
    report = _read_maester_latest()
    if not report:
        return {"available": False, "status": status}
    return {
        "available": True,
        "last_run": status.get("last_run"),
        "run_status": status.get("status"),
        "result": report.get("Result"),
        "tenant_name": report.get("TenantName"),
        "tenant_id": report.get("TenantId"),
        "total": report.get("TotalCount", 0),
        "passed": report.get("PassedCount", 0),
        "failed": report.get("FailedCount", 0),
        "skipped": report.get("SkippedCount", 0),
        "errors": report.get("ErrorCount", 0),
        "total_duration": report.get("TotalDuration"),
        "executed_at": report.get("ExecutedAt"),
        "maester_version": report.get("CurrentVersion", {}).get("Major", "?"),
    }


@app.get("/maester/tests")
async def maester_tests(result: str = None, severity: str = None, block: str = None, search: str = None):
    report = _read_maester_latest()
    if not report: raise HTTPException(status_code=404, detail="No Maester report found")
    tests = report.get("Tests", [])
    if result: tests = [t for t in tests if t.get("Result", "").lower() == result.lower()]
    if severity: tests = [t for t in tests if t.get("Severity", "").lower() == severity.lower()]
    if block: tests = [t for t in tests if t.get("Block", "").lower() == block.lower()]
    if search:
        s = search.lower()
        tests = [t for t in tests if s in t.get("Title", "").lower() or s in t.get("Id", "").lower()]
    return {"count": len(tests), "tests": [
        {
            "id": t.get("Id"), "title": t.get("Title"), "result": t.get("Result"),
            "severity": t.get("Severity"), "block": t.get("Block"), "duration": t.get("Duration"),
            "tags": t.get("Tag", []), "help_url": t.get("HelpUrl"),
            "test_result": (t.get("ResultDetail") or {}).get("TestResult"),
            "description": (t.get("ResultDetail") or {}).get("TestDescription", "")[:500],
            "skipped_reason": (t.get("ResultDetail") or {}).get("SkippedReason"),
            "error": t.get("ErrorRecord", []),
        } for t in tests
    ]}


@app.get("/maester/tests/{test_id}")
async def maester_test_detail(test_id: str):
    report = _read_maester_latest()
    if not report: raise HTTPException(status_code=404, detail="No Maester report found")
    test = next((t for t in report.get("Tests", []) if t.get("Id") == test_id), None)
    if not test: raise HTTPException(status_code=404, detail=f"Test {test_id} not found")
    return {
        "id": test.get("Id"), "title": test.get("Title"), "result": test.get("Result"),
        "severity": test.get("Severity"), "block": test.get("Block"), "duration": test.get("Duration"),
        "tags": test.get("Tag", []), "help_url": test.get("HelpUrl"),
        "script_block_file": test.get("ScriptBlockFile"),
        "test_result": test.get("ResultDetail", {}).get("TestResult"),
        "description": test.get("ResultDetail", {}).get("TestDescription"),
        "skipped_reason": test.get("ResultDetail", {}).get("SkippedReason"),
        "error": test.get("ErrorRecord", []),
    }


@app.get("/maester/summary")
async def maester_summary():
    report = _read_maester_latest()
    if not report: raise HTTPException(status_code=404, detail="No Maester report found")
    tests = report.get("Tests", [])
    by_block, by_severity, failed_high = {}, {}, []
    for t in tests:
        block = t.get("Block", "Unknown")
        result = t.get("Result", "Unknown")
        severity = t.get("Severity", "Unknown")
        if block not in by_block: by_block[block] = {"passed": 0, "failed": 0, "skipped": 0, "error": 0}
        if result == "Passed": by_block[block]["passed"] += 1
        elif result == "Failed": by_block[block]["failed"] += 1
        elif result == "Skipped": by_block[block]["skipped"] += 1
        else: by_block[block]["error"] += 1
        if severity not in by_severity: by_severity[severity] = {"passed": 0, "failed": 0}
        if result == "Passed": by_severity[severity]["passed"] += 1
        elif result == "Failed": by_severity[severity]["failed"] += 1
        if result == "Failed" and severity in ("High", "Critical"):
            failed_high.append({"id": t.get("Id"), "title": t.get("Title"), "severity": severity, "block": block})
    return {"by_block": by_block, "by_severity": by_severity, "failed_high_severity": failed_high[:20]}


# ── ScubaGear endpoints ───────────────────────────────────────────────────────

SCUBAGEAR_OUTPUT_DIR = os.getenv("SCUBAGEAR_OUTPUT_DIR", "/app/data/scubagear")

def _read_scubagear_latest() -> dict | None:
    path = os.path.join(SCUBAGEAR_OUTPUT_DIR, "latest.json")
    if not os.path.exists(path): return None
    with open(path) as f: return json.load(f)

def _read_scubagear_status() -> dict | None:
    path = os.path.join(SCUBAGEAR_OUTPUT_DIR, "status.json")
    if not os.path.exists(path): return None
    with open(path) as f: return json.load(f)


@app.get("/scubagear/status")
async def scubagear_status():
    status = _read_scubagear_status()
    if not status:
        return {"available": False, "message": "No ScubaGear output found. Run the scubagear container."}
    report = _read_scubagear_latest()
    if not report: return {"available": False, "status": status}
    meta = report.get("MetaData", {})
    summary = report.get("Summary", {})
    total_pass = sum(v.get("Passes", 0) for v in summary.values())
    total_fail = sum(v.get("Failures", 0) for v in summary.values())
    total_warn = sum(v.get("Warnings", 0) for v in summary.values())
    total_manual = sum(v.get("Manual", 0) for v in summary.values())
    total_errors = sum(v.get("Errors", 0) for v in summary.values())
    total = total_pass + total_fail + total_warn + total_manual + total_errors
    return {
        "available": True,
        "last_run": status.get("last_run"),
        "run_status": status.get("status"),
        "tenant": meta.get("Tenant", {}).get("TenantName"),
        "products": list(summary.keys()),
        "summary": summary,
        "total": total, "passed": total_pass, "failed": total_fail,
        "warnings": total_warn, "manual": total_manual, "errors": total_errors,
        "scubagear_version": meta.get("ScubaGearVersion"),
        "executed_at": meta.get("ExecutedAt"),
    }


@app.get("/scubagear/results")
async def scubagear_results(product: str = None, result: str = None, search: str = None):
    report = _read_scubagear_latest()
    if not report: raise HTTPException(status_code=404, detail="No ScubaGear report found")
    results = report.get("Results", {})
    controls = []
    for prod, groups in results.items():
        if product and prod.lower() != product.lower(): continue
        for group in groups:
            for ctrl in group.get("Controls", []):
                controls.append({
                    "product": prod, "group_name": group.get("GroupName"),
                    "group_number": group.get("GroupNumber"), "group_url": group.get("GroupReferenceURL"),
                    "control_id": ctrl.get("Control ID"), "requirement": ctrl.get("Requirement"),
                    "result": ctrl.get("Result"), "criticality": ctrl.get("Criticality"),
                    "details": ctrl.get("Details"), "resolution_date": ctrl.get("ResolutionDate"),
                })
    if result: controls = [c for c in controls if c.get("result", "").lower() == result.lower()]
    if search:
        s = search.lower()
        controls = [c for c in controls if s in (c.get("control_id") or "").lower() or s in (c.get("requirement") or "").lower()]
    return {"count": len(controls), "controls": controls}


@app.get("/scubagear/summary")
async def scubagear_summary():
    report = _read_scubagear_latest()
    if not report: raise HTTPException(status_code=404, detail="No ScubaGear report found")
    results = report.get("Results", {})
    failed_shall = []
    for prod, groups in results.items():
        for group in groups:
            for ctrl in group.get("Controls", []):
                if ctrl.get("Result") == "Fail" and ctrl.get("Criticality") == "Shall":
                    failed_shall.append({
                        "product": prod, "control_id": ctrl.get("Control ID"),
                        "requirement": ctrl.get("Requirement"), "details": ctrl.get("Details"),
                        "group_name": group.get("GroupName"),
                    })
    return {"by_product": report.get("Summary", {}), "failed_shall": failed_shall[:20]}


# ── Okta endpoints ────────────────────────────────────────────────────────────

@app.get("/okta/health")
async def okta_health():
    from okta import okta_available, get_users
    if not okta_available():
        return {"available": False, "message": "OKTA_DOMAIN and OKTA_API_TOKEN not set"}
    try:
        await get_users(limit=1)
        return {"available": True, "domain": os.getenv("OKTA_DOMAIN")}
    except Exception as e:
        return {"available": False, "message": str(e)}


@app.get("/okta/users")
async def okta_users(limit: int = 50, search: str = None):
    from okta import okta_available, get_users
    if not okta_available(): raise HTTPException(status_code=503, detail="Okta not configured")
    users = await get_users(limit=limit, search=search)
    return {"count": len(users), "users": [
        {
            "id": u.get("id"),
            "login": u.get("profile", {}).get("login"),
            "display_name": f"{u.get('profile',{}).get('firstName','')} {u.get('profile',{}).get('lastName','')}".strip(),
            "email": u.get("profile", {}).get("email"),
            "status": u.get("status"),
            "created": u.get("created"),
            "last_login": u.get("lastLogin"),
            "dept": u.get("profile", {}).get("department"),
            "title": u.get("profile", {}).get("title"),
        } for u in users
    ]}


@app.get("/okta/users/{user_id}")
async def okta_user(user_id: str):
    from okta import okta_available, enrich_user_from_okta
    if not okta_available(): raise HTTPException(status_code=503, detail="Okta not configured")
    return await enrich_user_from_okta(user_id)


@app.get("/okta/logs")
async def okta_logs(hours: int = 24, limit: int = 100):
    from okta import okta_available, get_logs
    if not okta_available(): raise HTTPException(status_code=503, detail="Okta not configured")
    logs = await get_logs(hours=hours, limit=limit)
    return {"count": len(logs), "logs": logs}


@app.get("/okta/logs/failed")
async def okta_failed_logins(hours: int = 24, limit: int = 50):
    from okta import okta_available, get_failed_logins
    if not okta_available(): raise HTTPException(status_code=503, detail="Okta not configured")
    logs = await get_failed_logins(hours=hours, limit=limit)
    return {"count": len(logs), "logs": logs}


@app.get("/okta/logs/suspicious")
async def okta_suspicious(hours: int = 48, limit: int = 50):
    from okta import okta_available, get_suspicious_activity
    if not okta_available(): raise HTTPException(status_code=503, detail="Okta not configured")
    logs = await get_suspicious_activity(hours=hours, limit=limit)
    return {"count": len(logs), "logs": logs}


@app.post("/okta/actions/suspend")
async def okta_suspend(body: dict):
    from okta import okta_available, suspend_user
    if not okta_available(): raise HTTPException(status_code=503, detail="Okta not configured")
    user_id = body.get("user_id")
    if not user_id: raise HTTPException(status_code=400, detail="user_id required")
    result = await suspend_user(user_id)
    conn = get_connection()
    conn.execute("INSERT INTO response_actions (action, target, performed_at, details, provider) VALUES (?,?,?,?,?)",
        ("okta_suspend", user_id, datetime.now(timezone.utc).isoformat(), json.dumps(result), "okta"))
    conn.commit(); conn.close()
    return result


@app.post("/okta/actions/unsuspend")
async def okta_unsuspend(body: dict):
    from okta import okta_available, unsuspend_user
    if not okta_available(): raise HTTPException(status_code=503, detail="Okta not configured")
    user_id = body.get("user_id")
    if not user_id: raise HTTPException(status_code=400, detail="user_id required")
    result = await unsuspend_user(user_id)
    conn = get_connection()
    conn.execute("INSERT INTO response_actions (action, target, performed_at, details, provider) VALUES (?,?,?,?,?)",
        ("okta_unsuspend", user_id, datetime.now(timezone.utc).isoformat(), json.dumps(result), "okta"))
    conn.commit(); conn.close()
    return result


@app.post("/okta/actions/clear-sessions")
async def okta_clear_sessions(body: dict):
    from okta import okta_available, clear_user_sessions
    if not okta_available(): raise HTTPException(status_code=503, detail="Okta not configured")
    user_id = body.get("user_id")
    if not user_id: raise HTTPException(status_code=400, detail="user_id required")
    result = await clear_user_sessions(user_id)
    conn = get_connection()
    conn.execute("INSERT INTO response_actions (action, target, performed_at, details, provider) VALUES (?,?,?,?,?)",
        ("okta_clear_sessions", user_id, datetime.now(timezone.utc).isoformat(), json.dumps(result), "okta"))
    conn.commit(); conn.close()
    return result


# ── Auth0 endpoints ───────────────────────────────────────────────────────────

@app.get("/auth0/health")
async def auth0_health():
    from auth0 import auth0_available, get_token
    if not auth0_available():
        return {"available": False, "message": "AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET not set"}
    try:
        await get_token()
        return {"available": True, "domain": os.getenv("AUTH0_DOMAIN")}
    except Exception as e:
        return {"available": False, "message": str(e)}


@app.get("/auth0/users")
async def auth0_users(per_page: int = 50, q: str = None):
    from auth0 import auth0_available, get_users
    if not auth0_available(): raise HTTPException(status_code=503, detail="Auth0 not configured")
    users = await get_users(per_page=per_page, q=q)
    return {"count": len(users), "users": [
        {
            "user_id": u.get("user_id"), "email": u.get("email"), "name": u.get("name"),
            "blocked": u.get("blocked", False), "email_verified": u.get("email_verified"),
            "created_at": u.get("created_at"), "last_login": u.get("last_login"),
            "last_ip": u.get("last_ip"), "logins_count": u.get("logins_count", 0),
            "identities": [i.get("provider") for i in u.get("identities", [])],
        } for u in users
    ]}


@app.get("/auth0/users/{user_id:path}")
async def auth0_user(user_id: str):
    from auth0 import auth0_available, enrich_user_from_auth0
    if not auth0_available(): raise HTTPException(status_code=503, detail="Auth0 not configured")
    return await enrich_user_from_auth0(user_id)


@app.get("/auth0/logs")
async def auth0_logs(per_page: int = 100, q: str = None):
    from auth0 import auth0_available, get_logs
    if not auth0_available(): raise HTTPException(status_code=503, detail="Auth0 not configured")
    logs = await get_logs(per_page=per_page, q=q)
    return {"count": len(logs), "logs": logs}


@app.get("/auth0/logs/failed")
async def auth0_failed_logins(per_page: int = 50):
    from auth0 import auth0_available, get_failed_logins
    if not auth0_available(): raise HTTPException(status_code=503, detail="Auth0 not configured")
    logs = await get_failed_logins(per_page=per_page)
    return {"count": len(logs), "logs": logs}


@app.get("/auth0/logs/suspicious")
async def auth0_suspicious(per_page: int = 50):
    from auth0 import auth0_available, get_suspicious_logins
    if not auth0_available(): raise HTTPException(status_code=503, detail="Auth0 not configured")
    logs = await get_suspicious_logins(per_page=per_page)
    return {"count": len(logs), "logs": logs}


@app.get("/auth0/attack-protection")
async def auth0_attack_protection():
    from auth0 import auth0_available, get_brute_force_config, get_suspicious_ip_config, get_breached_password_config
    if not auth0_available(): raise HTTPException(status_code=503, detail="Auth0 not configured")
    brute, suspicious, breached = await asyncio.gather(
        get_brute_force_config(), get_suspicious_ip_config(), get_breached_password_config(),
        return_exceptions=True,
    )
    return {
        "brute_force": brute if not isinstance(brute, Exception) else {},
        "suspicious_ip": suspicious if not isinstance(suspicious, Exception) else {},
        "breached_password": breached if not isinstance(breached, Exception) else {},
    }


@app.post("/auth0/actions/block")
async def auth0_block_user(body: dict):
    from auth0 import auth0_available, block_user
    if not auth0_available(): raise HTTPException(status_code=503, detail="Auth0 not configured")
    user_id = body.get("user_id")
    if not user_id: raise HTTPException(status_code=400, detail="user_id required")
    result = await block_user(user_id)
    conn = get_connection()
    conn.execute("INSERT INTO response_actions (action, target, performed_at, details, provider) VALUES (?,?,?,?,?)",
        ("auth0_block", user_id, datetime.now(timezone.utc).isoformat(), json.dumps(result), "auth0"))
    conn.commit(); conn.close()
    return result


@app.post("/auth0/actions/unblock")
async def auth0_unblock_user(body: dict):
    from auth0 import auth0_available, unblock_user
    if not auth0_available(): raise HTTPException(status_code=503, detail="Auth0 not configured")
    user_id = body.get("user_id")
    if not user_id: raise HTTPException(status_code=400, detail="user_id required")
    result = await unblock_user(user_id)
    conn = get_connection()
    conn.execute("INSERT INTO response_actions (action, target, performed_at, details, provider) VALUES (?,?,?,?,?)",
        ("auth0_unblock", user_id, datetime.now(timezone.utc).isoformat(), json.dumps(result), "auth0"))
    conn.commit(); conn.close()
    return result

# Patch instructions for soc-agent/main.py
# 
# 1. Add import at top (after existing imports):
from velociraptor import hunt_host, get_clients, create_hunt, velo_available

# 2. Replace the /investigate endpoint (lines 62-82) with:
@app.post("/investigate")
async def investigate_alert(alert: dict):
    prior_cases = correlate(alert)
    result = await triage(alert)
    report = generate_ir_report(alert, result)
    blast = await estimate_blast_radius(alert, report)
    report["blast_radius"] = blast
    attacker_ips = blast.get("attacker_ips", [])
    report["threat_intel"] = await enrich_ips(attacker_ips) if attacker_ips else {}
    if prior_cases:
        report["prior_cases"] = prior_cases
        report["repeated_attacker"] = True
    else:
        report["prior_cases"] = []
        report["repeated_attacker"] = False

    # Velociraptor: hunt affected hosts for endpoint telemetry
    alert_type = report.get("alert_type", "default")
    affected_hosts = blast.get("affected_hosts", []) + attacker_ips
    velo_results = {}
    if velo_available() and affected_hosts:
        for host in affected_hosts[:3]:  # cap at 3 hosts to avoid long delays
            velo_results[host] = await hunt_host(host, alert_type)
    if velo_results:
        report["velociraptor"] = velo_results

    case_id = save_report(report, alert)
    report["case_id"] = case_id
    conn = get_connection()
    report["playbook_executions"] = await run_playbooks(report, db_conn=conn)
    conn.close()
    return report

# 3. Add new endpoints before the last line of the file:

@app.get("/velociraptor/status")
async def velociraptor_status():
    available = velo_available()
    clients = await get_clients() if available else []
    return {
        "available": available,
        "client_count": len(clients),
        "clients": clients[:20],
    }

@app.post("/velociraptor/hunt")
async def velociraptor_hunt(body: dict):
    """Manually trigger a Velociraptor hunt from the UI."""
    if not velo_available():
        raise HTTPException(status_code=503, detail="Velociraptor not available")
    host = body.get("host")
    artifact = body.get("artifact", "Linux.Sys.Pslist")
    alert_type = body.get("alert_type", "default")
    if host:
        result = await hunt_host(host, alert_type)
    else:
        hunt_id = await create_hunt(
            artifact=artifact,
            description=body.get("description", "TriagaSOAR manual hunt"),
        )
        result = {"hunt_id": hunt_id, "artifact": artifact}
    return result