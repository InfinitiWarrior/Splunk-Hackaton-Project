import sqlite3
import json
import os
import re
from datetime import datetime, timezone

DB_PATH = os.getenv("DB_PATH", "/app/data/cases.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            title TEXT,
            severity TEXT,
            alert_type TEXT,
            confidence REAL,
            kill_chain TEXT,
            summary TEXT,
            full_report TEXT,
            verdict TEXT DEFAULT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS monitor_state (
            search_name TEXT PRIMARY KEY,
            last_investigated TEXT,
            last_result_count INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS response_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            performed_at TEXT NOT NULL,
            details TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS playbook_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            playbook_id TEXT NOT NULL,
            playbook_name TEXT NOT NULL,
            report_id TEXT NOT NULL,
            triggered_at TEXT NOT NULL,
            action_results TEXT,
            overall_status TEXT NOT NULL DEFAULT 'ok'
        )
    """)

    # Migrations — add columns that may not exist in older DBs
    for migration in [
        "ALTER TABLE cases ADD COLUMN verdict TEXT DEFAULT NULL",
        "ALTER TABLE response_actions ADD COLUMN provider TEXT DEFAULT NULL",
    ]:
        try:
            conn.execute(migration)
        except Exception:
            pass

    conn.commit()
    conn.close()


def save_report(report: dict, alert: dict) -> int:
    conn = get_connection()
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute("""
            INSERT OR REPLACE INTO cases
            (report_id, created_at, title, severity, alert_type, confidence, kill_chain, summary, full_report)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report.get("report_id"),
            now,
            alert.get("title"),
            report.get("severity"),
            report.get("alert_type"),
            report.get("final_confidence", 0),
            report.get("kill_chain_summary", ""),
            report.get("summary", ""),
            json.dumps(report),
        ))
        case_id = conn.execute(
            "SELECT id FROM cases WHERE report_id = ?", (report.get("report_id"),)
        ).fetchone()["id"]

        extract_entities(conn, case_id, report)
        conn.commit()
        return case_id
    finally:
        conn.close()


def extract_entities(conn, case_id: int, report: dict):
    blast = report.get("blast_radius", {})
    entities = []

    for ip in blast.get("attacker_ips", []):
        entities.append(("ip", ip))
    for user in blast.get("compromised_users", []):
        if user.lower() not in ("root", "admin", "user", "the", "a"):
            entities.append(("user", user))
    for host in blast.get("affected_hosts", []):
        entities.append(("host", host))

    conn.execute("DELETE FROM entities WHERE case_id = ?", (case_id,))
    for etype, evalue in entities:
        conn.execute(
            "INSERT INTO entities (case_id, type, value) VALUES (?, ?, ?)",
            (case_id, etype, evalue)
        )


def correlate(alert: dict) -> list:
    search_terms = alert.get("search_terms", "")
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", search_terms)
    users = re.findall(r'"([a-zA-Z0-9_-]+)"', search_terms)

    if not ips and not users:
        return []

    conn = get_connection()
    try:
        results = []
        for ip in ips:
            rows = conn.execute("""
                SELECT c.report_id, c.title, c.severity, c.kill_chain, c.created_at
                FROM cases c
                JOIN entities e ON e.case_id = c.id
                WHERE e.type = 'ip' AND e.value = ?
                ORDER BY c.created_at DESC LIMIT 5
            """, (ip,)).fetchall()
            for row in rows:
                results.append({**dict(row), "matched_entity": {"type": "ip", "value": ip}})

        for user in users:
            rows = conn.execute("""
                SELECT c.report_id, c.title, c.severity, c.kill_chain, c.created_at
                FROM cases c
                JOIN entities e ON e.case_id = c.id
                WHERE e.type = 'user' AND e.value = ?
                ORDER BY c.created_at DESC LIMIT 3
            """, (user,)).fetchall()
            for row in rows:
                results.append({**dict(row), "matched_entity": {"type": "user", "value": user}})

        return results
    finally:
        conn.close()


def get_all_cases() -> list:
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT report_id, created_at, title, severity, alert_type,
                   confidence, kill_chain, summary, verdict
            FROM cases ORDER BY created_at DESC
        """).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_case(report_id: str) -> dict | None:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM cases WHERE report_id = ?", (report_id,)
        ).fetchone()
        if not row:
            return None
        data = dict(row)
        full = json.loads(data.pop("full_report", "{}"))
        full["verdict"] = data.get("verdict")
        return full
    finally:
        conn.close()


def set_verdict(report_id: str, verdict: str) -> bool:
    if verdict not in ("confirmed", "false_positive", None):
        return False
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE cases SET verdict = ? WHERE report_id = ?",
            (verdict, report_id)
        )
        conn.commit()
        return conn.execute("SELECT changes()").fetchone()[0] > 0
    finally:
        conn.close()


def get_playbook_executions(report_id: str = None, limit: int = 100) -> list:
    conn = get_connection()
    try:
        if report_id:
            rows = conn.execute("""
                SELECT * FROM playbook_executions
                WHERE report_id = ?
                ORDER BY triggered_at DESC LIMIT ?
            """, (report_id, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM playbook_executions
                ORDER BY triggered_at DESC LIMIT ?
            """, (limit,)).fetchall()
        result = []
        for row in rows:
            r = dict(row)
            r["action_results"] = json.loads(r.get("action_results") or "[]")
            result.append(r)
        return result
    finally:
        conn.close()


def get_stats() -> dict:
    conn = get_connection()
    try:
        total = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        confirmed = conn.execute(
            "SELECT COUNT(*) FROM cases WHERE verdict = 'confirmed'"
        ).fetchone()[0]
        false_positive = conn.execute(
            "SELECT COUNT(*) FROM cases WHERE verdict = 'false_positive'"
        ).fetchone()[0]
        unreviewed = conn.execute(
            "SELECT COUNT(*) FROM cases WHERE verdict IS NULL"
        ).fetchone()[0]

        by_severity = {}
        for row in conn.execute(
            "SELECT severity, COUNT(*) as count FROM cases GROUP BY severity"
        ).fetchall():
            by_severity[row["severity"]] = row["count"]

        fp_by_type = {}
        for row in conn.execute("""
            SELECT alert_type, COUNT(*) as count FROM cases
            WHERE verdict = 'false_positive' GROUP BY alert_type
        """).fetchall():
            fp_by_type[row["alert_type"]] = row["count"]

        playbook_runs = conn.execute(
            "SELECT COUNT(*) FROM playbook_executions"
        ).fetchone()[0]

        return {
            "total": total,
            "confirmed": confirmed,
            "false_positive": false_positive,
            "unreviewed": unreviewed,
            "by_severity": by_severity,
            "false_positive_by_type": fp_by_type,
            "fp_rate": round(false_positive / total * 100, 1) if total > 0 else 0,
            "playbook_executions": playbook_runs,
        }
    finally:
        conn.close()