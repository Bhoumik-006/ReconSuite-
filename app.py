#!/usr/bin/env python3
"""
ReconSuite v2.0 — Web Dashboard (Flask + SQLite)
Provides REST API endpoints, persistent scan history, scheduled scans, and a dark-theme SPA.
"""

import hmac
import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from flask import Flask, jsonify, request, send_file, send_from_directory, render_template

import recon_cli

# ── Config ────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="templates")
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET", "reconsuite-v2-secret-change-me")
API_TOKEN = os.environ.get("RECONSUITE_API_TOKEN", "").strip()
DB_PATH = Path("scans") / "recon.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)
SCREENSHOT_DIR = Path("screenshots")
SCREENSHOT_DIR.mkdir(exist_ok=True)
SCAN_PROGRESS: Dict[str, Dict] = {}

def is_valid_target(target: str) -> bool:
    """Accept valid domain names or IP addresses (v4 and v6)."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    return bool(re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{1,253}(\.[a-zA-Z]{2,})+$', target))

def _token_from_request() -> str:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return request.headers.get("X-API-Token", request.args.get("token", "")).strip()

@app.before_request
def require_api_token():
    if not API_TOKEN:
        return None
    protected = request.path.startswith("/api/") or request.path.startswith("/screenshots/")
    if protected and _token_from_request() != API_TOKEN:
        return jsonify({"error": "API token required"}), 401
    return None

def normalize_modules(raw_modules, cve=False, screenshots=False) -> Dict[str, bool]:
    all_modules = [
        "whois", "dns", "subdomains", "subdomain_brute", "subdomain_passive",
        "ports", "headers", "fingerprint", "ssl", "emails", "email_google",
        "email_bing", "shodan", "crawl", "cve", "screenshots"
    ]
    defaults = {m: True for m in all_modules}
    defaults["cve"] = bool(cve)
    defaults["screenshots"] = bool(screenshots)

    if isinstance(raw_modules, str):
        try:
            raw_modules = json.loads(raw_modules) if raw_modules.strip() else {}
        except json.JSONDecodeError:
            raw_modules = {}
    if isinstance(raw_modules, dict) and raw_modules:
        for module in all_modules:
            if module in raw_modules:
                defaults[module] = bool(raw_modules[module])

    if not defaults["subdomains"]:
        defaults["subdomain_brute"] = False
        defaults["subdomain_passive"] = False
    if not defaults["emails"]:
        defaults["email_google"] = False
        defaults["email_bing"] = False
    return defaults

# ── DB Setup ──────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            started_at TEXT,
            completed_at TEXT,
            duration REAL,
            modules TEXT DEFAULT '{}',
            results TEXT DEFAULT '{}',
            error TEXT,
            scan_type TEXT DEFAULT 'manual'
        );
        CREATE TABLE IF NOT EXISTS scheduled_scans (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            target TEXT NOT NULL,
            cron_expression TEXT NOT NULL,
            modules TEXT DEFAULT '{}',
            enabled INTEGER DEFAULT 1,
            last_run TEXT,
            next_run TEXT
        );
        CREATE TABLE IF NOT EXISTS scan_history (
            id TEXT PRIMARY KEY,
            scan_id TEXT,
            diff_type TEXT,
            old_data TEXT,
            new_data TEXT,
            detected_at TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
        CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at);
    """)
    conn.commit()
    conn.close()

init_db()

# ── APScheduler Setup ────────────────────────────────────────────────
scheduler = BackgroundScheduler()
scheduler.start()

def run_scheduled_scan(scan_id: str, target: str, modules: Dict[str, bool]):
    """Background job that runs a scan and stores results."""
    def progress_callback(module: str, completed: int, total: int):
        if scan_id in SCAN_PROGRESS:
            percent = (completed / total) * 100 if total > 0 else 0
            SCAN_PROGRESS[scan_id] = {
                "module": module,
                "completed": completed,
                "total": total,
                "percent": round(percent, 2)
            }

    SCAN_PROGRESS[scan_id] = {"module": "initializing", "completed": 0, "total": 1, "percent": 0}
    conn = get_db()
    conn.execute("UPDATE scans SET status='running', started_at=? WHERE id=?",
                 (datetime.now().isoformat(), scan_id))
    conn.commit()
    conn.close()
    try:
        recon_cli.configure_proxy()
        result = recon_cli.full_scan(target, modules, progress_callback=progress_callback)
        conn = get_db()
        conn.execute(
            "UPDATE scans SET status='completed', completed_at=?, duration=?, results=? WHERE id=?",
            (datetime.now().isoformat(), result.get("scan_duration", 0),
             json.dumps(result, default=str), scan_id))
        conn.commit()
        conn.close()
        # Export reports
        safe_name = re.sub(r"[^a-zA-Z0-9]", "_", target)
        recon_cli.export_reports(result, safe_name, ["json", "md"])
    except Exception as e:
        conn = get_db()
        conn.execute("UPDATE scans SET status='failed', error=? WHERE id=?",
                     (str(e), scan_id))
        conn.commit()
        conn.close()
    finally:
        if scan_id in SCAN_PROGRESS:
            del SCAN_PROGRESS[scan_id]

def add_scheduled_job(sched_id: str, name: str, target: str, cron_expr: str, modules: Dict[str, bool]):
    """Add a scheduled scan job to APScheduler."""
    try:
        trigger = CronTrigger.from_crontab(cron_expr)
        scheduler.add_job(
            func=lambda: _execute_scheduled(sched_id, target, modules),
            trigger=trigger,
            id=sched_id,
            name=name,
            replace_existing=True,
            misfire_grace_time=300
        )
    except Exception as e:
        print(f"Failed to schedule job: {e}")

def _execute_scheduled(sched_id: str, target: str, modules: Dict[str, bool]):
    """Execute a scheduled scan and diff against previous results."""
    scan_id = str(uuid.uuid4())
    conn = get_db()
    # Get previous results for diff
    prev = conn.execute(
        "SELECT results FROM scans WHERE target=? AND status='completed' ORDER BY completed_at DESC LIMIT 1",
        (target,)).fetchone()
    prev_results = json.loads(prev["results"]) if prev else None

    conn.execute("INSERT INTO scans (id, target, status, started_at, modules, scan_type) VALUES (?,?,?,?,?,?)",
                 (scan_id, target, "running", datetime.now().isoformat(), json.dumps(modules), "scheduled"))
    conn.execute("UPDATE scheduled_scans SET last_run=? WHERE id=?", (datetime.now().isoformat(), sched_id))
    conn.commit()
    conn.close()

    try:
        recon_cli.configure_proxy()
        result = recon_cli.full_scan(target, modules)
        conn = get_db()
        conn.execute(
            "UPDATE scans SET status='completed', completed_at=?, duration=?, results=? WHERE id=?",
            (datetime.now().isoformat(), result.get("scan_duration", 0),
             json.dumps(result, default=str), scan_id))
        conn.commit()
        conn.close()
        safe_name = re.sub(r"[^a-zA-Z0-9]", "_", target)
        recon_cli.export_reports(result, safe_name, ["json", "md"])

        # Diff alerting
        if prev_results:
            _generate_diff_alert(scan_id, target, prev_results, result)
    except Exception as e:
        conn = get_db()
        conn.execute("UPDATE scans SET status='failed', error=? WHERE id=?", (str(e), scan_id))
        conn.commit()
        conn.close()

def _generate_diff_alert(scan_id: str, target: str, old: Dict, new: Dict):
    """Compare two scan results and record differences."""
    conn = get_db()
    # Compare subdomains
    old_subs = set(old.get("modules", {}).get("subdomains", {}).get("all", []))
    new_subs = set(new.get("modules", {}).get("subdomains", {}).get("all", []))
    added_subs = new_subs - old_subs
    removed_subs = old_subs - new_subs
    if added_subs:
        conn.execute("INSERT INTO scan_history (id, scan_id, diff_type, old_data, new_data, detected_at) VALUES (?,?,?,?,?,?)",
                     (str(uuid.uuid4()), scan_id, "subdomain_added", "[]", json.dumps(list(added_subs)), datetime.now().isoformat()))
    if removed_subs:
        conn.execute("INSERT INTO scan_history (id, scan_id, diff_type, old_data, new_data, detected_at) VALUES (?,?,?,?,?,?)",
                     (str(uuid.uuid4()), scan_id, "subdomain_removed", json.dumps(list(removed_subs)), "[]", datetime.now().isoformat()))
    # Compare ports
    old_ports = set(old.get("modules", {}).get("ports", {}).get("open_ports", []))
    new_ports = set(new.get("modules", {}).get("ports", {}).get("open_ports", []))
    added_ports = new_ports - old_ports
    if added_ports:
        conn.execute("INSERT INTO scan_history (id, scan_id, diff_type, old_data, new_data, detected_at) VALUES (?,?,?,?,?,?)",
                     (str(uuid.uuid4()), scan_id, "port_added", "[]", json.dumps(list(added_ports)), datetime.now().isoformat()))
    conn.commit()
    conn.close()

# Load existing schedules on startup
def load_schedules():
    conn = get_db()
    rows = conn.execute("SELECT * FROM scheduled_scans WHERE enabled=1").fetchall()
    conn.close()
    for row in rows:
        modules = json.loads(row["modules"]) if row["modules"] else {}
        add_scheduled_job(row["id"], row["name"], row["target"], row["cron_expression"], modules)
load_schedules()

# ═════════════════════════════════════════════════════════════════════
# ROUTES
# ═════════════════════════════════════════════════════════════════════

# ── Dashboard ────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("dashboard.html")

# ── API: Start Scan ──────────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
def api_start_scan():
    data = request.get_json() or {}
    target = data.get("target", "").strip().lower()
    if not target:
        return jsonify({"error": "No target provided"}), 400
    if not is_valid_target(target):
        return jsonify({"error": "Invalid target — enter a domain (example.com) or IP address"}), 400

    modules = normalize_modules(
        data.get("modules", {}),
        cve=data.get("cve", False),
        screenshots=data.get("screenshots", False)
    )

    scan_id = str(uuid.uuid4())
    conn = get_db()
    conn.execute("INSERT INTO scans (id, target, status, started_at, modules, scan_type) VALUES (?,?,?,?,?,?)",
                 (scan_id, target, "running", datetime.now().isoformat(), json.dumps(modules), "manual"))
    conn.commit()
    conn.close()

    # Run in background thread
    thread = threading.Thread(target=run_scheduled_scan, args=(scan_id, target, modules))
    thread.daemon = True
    thread.start()

    return jsonify({"scan_id": scan_id, "status": "started", "target": target}), 202

# ── API: Scan Status ─────────────────────────────────────────────────
@app.route("/api/scan/<scan_id>")
def api_scan_status(scan_id: str):
    conn = get_db()
    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Scan not found"}), 404
    
    data = dict(row)
    if data["status"] == "running" and scan_id in SCAN_PROGRESS:
        data["progress"] = SCAN_PROGRESS[scan_id]
    return jsonify(data)

# ── API: List Scans ──────────────────────────────────────────────────
@app.route("/api/scans")
def api_list_scans():
    target = request.args.get("target", "")
    limit = min(int(request.args.get("limit", 50)), 200)
    conn = get_db()
    if target:
        rows = conn.execute(
            "SELECT * FROM scans WHERE target=? ORDER BY started_at DESC LIMIT ?",
            (target, limit)).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ── API: List Results for Target ─────────────────────────────────────
@app.route("/api/results/<target>")
def api_results(target: str):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM scans WHERE target=? AND status='completed' ORDER BY completed_at DESC LIMIT 1",
        (target,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "No results found"}), 404
    return jsonify({"results": json.loads(row["results"]) if row["results"] else {}})

# ── API: Get Scan History / Diffs ────────────────────────────────────
@app.route("/api/history")
def api_history():
    target = request.args.get("target", "")
    conn = get_db()
    if target:
        rows = conn.execute(
            """SELECT h.* FROM scan_history h
               JOIN scans s ON h.scan_id = s.id
               WHERE s.target=? ORDER BY h.detected_at DESC LIMIT 100""",
            (target,)).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM scan_history ORDER BY detected_at DESC LIMIT 100").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ── API: Delete Scan ─────────────────────────────────────────────────
@app.route("/api/scan/<scan_id>", methods=["DELETE"])
def api_delete_scan(scan_id: str):
    conn = get_db()
    conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    conn.execute("DELETE FROM scan_history WHERE scan_id=?", (scan_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted"})

# ── API: Reports ─────────────────────────────────────────────────────
@app.route("/api/reports")
def api_list_reports():
    files = sorted(REPORT_DIR.iterdir(), key=os.path.getmtime, reverse=True)
    reports = []
    for f in files:
        if f.suffix in (".json", ".md", ".pdf"):
            reports.append({
                "name": f.name,
                "path": f.name,
                "size": f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                "type": f.suffix[1:]
            })
    return jsonify(reports)

@app.route("/api/reports/<path:filename>")
def api_download_report(filename: str):
    safe = Path(filename).name  # prevent path traversal
    report_path = REPORT_DIR / safe
    if not report_path.exists():
        return jsonify({"error": "Report not found"}), 404
    return send_file(str(report_path), as_attachment=True)

# ── API: Screenshots ─────────────────────────────────────────────────
@app.route("/api/screenshots")
def api_list_screenshots():
    files = sorted(SCREENSHOT_DIR.iterdir(), key=os.path.getmtime, reverse=True)
    screenshots = []
    for f in files:
        if f.suffix == ".png":
            screenshots.append({
                "name": f.name,
                "path": f.name,
                "size": f.stat().st_size,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat()
            })
    return jsonify(screenshots)

@app.route("/screenshots/<path:filename>")
def api_serve_screenshot(filename: str):
    safe = Path(filename).name
    return send_file(str(SCREENSHOT_DIR / safe), mimetype="image/png")

# ── API: Scheduled Scans ─────────────────────────────────────────────
@app.route("/api/schedules", methods=["GET"])
def api_list_schedules():
    conn = get_db()
    rows = conn.execute("SELECT * FROM scheduled_scans ORDER BY name").fetchall()
    conn.close()
    schedules = []
    for row in rows:
        item = dict(row)
        try:
            item["modules"] = json.loads(item["modules"]) if item.get("modules") else {}
        except (TypeError, json.JSONDecodeError):
            item["modules"] = {}
        schedules.append(item)
    return jsonify(schedules)

@app.route("/api/schedules", methods=["POST"])
def api_create_schedule():
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    target = data.get("target", "").strip().lower()
    cron = data.get("cron_expression", "0 */6 * * *").strip()
    modules = normalize_modules(data.get("modules", {}))

    if not name or not target:
        return jsonify({"error": "Name and target required"}), 400
    if not is_valid_target(target):
        return jsonify({"error": "Invalid target — enter a domain (example.com) or IP address"}), 400

    # Validate cron expression before saving
    try:
        CronTrigger.from_crontab(cron)
    except Exception:
        return jsonify({"error": f"Invalid cron expression: '{cron}'. Use 5-field format e.g. '0 */6 * * *'"}), 400

    sched_id = str(uuid.uuid4())
    conn = get_db()
    conn.execute(
        "INSERT INTO scheduled_scans (id, name, target, cron_expression, modules, enabled) VALUES (?,?,?,?,?,1)",
        (sched_id, name, target, cron, json.dumps(modules)))
    conn.commit()
    conn.close()

    add_scheduled_job(sched_id, name, target, cron, modules)
    return jsonify({"id": sched_id, "status": "created"}), 201

@app.route("/api/schedules/<schedule_id>", methods=["PUT"])
def api_update_schedule(schedule_id: str):
    data = request.get_json() or {}
    conn = get_db()
    row = conn.execute("SELECT * FROM scheduled_scans WHERE id=?", (schedule_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Schedule not found"}), 404

    name = data.get("name", row["name"])
    target = data.get("target", row["target"])
    cron = data.get("cron_expression", row["cron_expression"])
    modules = normalize_modules(row["modules"] if row["modules"] else {})
    if data.get("modules"):
        modules = normalize_modules(data["modules"])
    enabled = data.get("enabled", row["enabled"])

    conn.execute("UPDATE scheduled_scans SET name=?, target=?, cron_expression=?, modules=?, enabled=? WHERE id=?",
                 (name, target, cron, json.dumps(modules), enabled, schedule_id))
    conn.commit()
    conn.close()

    if enabled:
        add_scheduled_job(schedule_id, name, target, cron, modules)
    else:
        try:
            scheduler.remove_job(schedule_id)
        except Exception:
            pass
    return jsonify({"status": "updated"})

@app.route("/api/schedules/<schedule_id>", methods=["DELETE"])
def api_delete_schedule(schedule_id: str):
    conn = get_db()
    conn.execute("DELETE FROM scheduled_scans WHERE id=?", (schedule_id,))
    conn.commit()
    conn.close()
    try:
        scheduler.remove_job(schedule_id)
    except Exception:
        pass
    return jsonify({"status": "deleted"})

# ── API: Target Info ──────────────────────────────────────────────────
@app.route("/api/targets")
def api_targets():
    conn = get_db()
    rows = conn.execute(
        "SELECT target, COUNT(*) as scan_count, MAX(started_at) as last_scan FROM scans GROUP BY target ORDER BY last_scan DESC"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ── API: Stats ────────────────────────────────────────────────────────
@app.route("/api/stats")
def api_stats():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) as c FROM scans").fetchone()["c"]
    completed = conn.execute("SELECT COUNT(*) as c FROM scans WHERE status='completed'").fetchone()["c"]
    failed = conn.execute("SELECT COUNT(*) as c FROM scans WHERE status='failed'").fetchone()["c"]
    running = conn.execute("SELECT COUNT(*) as c FROM scans WHERE status='running'").fetchone()["c"]
    targets = conn.execute("SELECT COUNT(DISTINCT target) as c FROM scans").fetchone()["c"]
    schedules = conn.execute("SELECT COUNT(*) as c FROM scheduled_scans WHERE enabled=1").fetchone()["c"]
    conn.close()
    return jsonify({
        "total_scans": total,
        "completed": completed,
        "failed": failed,
        "running": running,
        "unique_targets": targets,
        "active_schedules": schedules
    })

# ── API: Proxy Config ────────────────────────────────────────────────
@app.route("/api/proxy", methods=["POST"])
def api_set_proxy():
    data = request.get_json() or {}
    proxy_url = data.get("proxy_url", "")
    use_tor = data.get("use_tor", False)
    recon_cli.configure_proxy(proxy_url if proxy_url else None, use_tor)
    return jsonify({"status": "proxy_configured", "proxy": proxy_url or ("tor" if use_tor else "none")})

# ── API: Status ──────────────────────────────────────────────────────
@app.route("/api/status")
def api_status():
    return jsonify({
        "app": "ReconSuite v2.0",
        "status": "running",
        "uptime": "N/A",
        "version": "2.0.0"
    })

# ═════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    print(f"ReconSuite v2.0 Dashboard running on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
