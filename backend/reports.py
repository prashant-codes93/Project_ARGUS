"""Account-scoped ARGUS report generation and saved snapshots."""
import json
from collections import Counter
from datetime import date, datetime, timezone

from flask import jsonify, request
from backend.auth import require_auth


CATEGORIES = {
    "overview": ("event", "threat", "incident", "investigation", "asset"),
    "risk": ("incident", "asset"),
    **{k: (k,) for k in ("event", "threat", "incident", "investigation", "asset")},
}
COLUMNS = {
    "event": ("Event ID", "Type", "Severity", "Source IP", "User", "Created"),
    "threat": ("Detection ID", "Rule", "Event ID", "Severity", "Source IP", "Detected"),
    "incident": ("Incident ID", "Title", "Risk score", "Level", "Status", "Created"),
    "investigation": ("Investigation ID", "Title", "Related incident", "Severity", "Analyst", "Status", "Created"),
    "asset": ("Asset ID", "Name", "Type", "IP address", "Criticality", "Security status", "Highest linked risk"),
}
LABELS = dict(event="Events", threat="Detections", incident="Incidents", investigation="Investigations", asset="Assets")


def read_source(conn, uid):
    def rows(sql):
        return [dict(row) for row in conn.execute(sql, (uid,))]
    events = rows("""SELECT e.id,e.timestamp,e.event_type,e.severity,e.source_ip,e.dest_ip,e.user
                     FROM events e JOIN scan_sessions s ON s.id=e.scan_id WHERE s.user_id=?""")
    detections = rows("""SELECT d.id,d.rule,d.severity,d.detected_at,d.event_id
                         FROM detection_matches d JOIN events e ON e.id=d.event_id
                         JOIN scan_sessions s ON s.id=e.scan_id WHERE s.user_id=?""")
    incidents = rows("SELECT * FROM incidents WHERE user_id=?")
    cases = rows("SELECT * FROM investigation_cases WHERE user_id=?")
    assets = rows("SELECT * FROM asset_inventory WHERE user_id=?")
    source = {kind: [] for kind in COLUMNS}
    def add(kind, values, time="", severity="", status="", ips=()):
        source[kind].append(dict(values=values, time=time or "", severity=str(severity or "").lower(),
                                 status=str(status or "").lower().replace("_", " "), ips=set(ips)-{None, ""}))
    by_event = {e["id"]: e for e in events}
    def addresses(e):
        return (e.get("source_ip"), e.get("dest_ip"))
    for e in events:
        add("event", [f"EV-{e['id']}", e["event_type"], e["severity"], e["source_ip"], e["user"], e["timestamp"]],
            e["timestamp"], e["severity"], ips=addresses(e))
    for d in detections:
        e = by_event[d["event_id"]]
        add("threat", [d["id"], d["rule"], f"EV-{e['id']}", d["severity"], e["source_ip"], d["detected_at"]],
            d["detected_at"], d["severity"], ips=addresses(e))
    incident_ips, ip_scores = {}, {}
    for i in incidents:
        linked = json.loads(i.get("event_ids") or "[]")
        ips = {ip for eid in linked for ip in addresses(by_event.get(eid, {})) if ip}
        incident_ips[i["id"]] = ips
        score = i["risk_score"]
        for ip in ips:
            if score is not None:
                ip_scores[ip] = max(score, ip_scores.get(ip, score))
        add("incident", [f"INC-{i['id']}", i["title"], score, i["risk_level"], i.get("status"), i["created_at"]],
            i["created_at"], i["risk_level"], i.get("status"), ips)
    for c in cases:
        incident = c.get("incident_id")
        add("investigation", [f"INV-{c['id']}", c["title"], f"INC-{incident}" if incident else None,
            c.get("severity"), c.get("assigned_analyst") or c.get("analyst") or c.get("assigned_to"), c.get("status"), c["created_at"]],
            c["created_at"], c.get("severity"), c.get("status"), incident_ips.get(incident, ()))
    for a in assets:
        ip = a.get("ip_address") or a.get("ip")
        crit = a.get("criticality") or a.get("business_criticality")
        add("asset", [f"A-{a['id']:03}", a.get("name") or a.get("asset_name"), a.get("asset_type") or a.get("type"),
            ip, crit, a.get("security_status"), ip_scores.get(ip)], severity=crit, ips=[ip])
    return source


def build(source, cfg):
    summary, charts, tables, findings = [], [], [], []
    for kind in CATEGORIES[cfg["type"]]:
        selected = []
        for row in source[kind]:
            if kind != "asset" and not cfg["start"] <= row["time"][:10] <= cfg["end"]:
                continue
            if cfg["sev"] and cfg["sev"] != row["severity"]:
                continue
            if cfg["asset"] and cfg["asset"] not in row["ips"]:
                continue
            if cfg["status"] and kind in ("incident", "investigation"):
                group = {"resolved": "closed", "acknowledged": "in progress", "investigating": "in progress",
                         "under review": "in progress"}.get(row["status"], row["status"])
                if group != cfg["status"]:
                    continue
            selected.append(row)
        selected.sort(key=lambda r: r["time"], reverse=True)
        if kind == "incident" and cfg["type"] == "risk":
            selected.sort(key=lambda r: r["values"][2] if r["values"][2] is not None else -1, reverse=True)
            scores = [r["values"][2] for r in selected if r["values"][2] is not None]
            if scores:
                summary.extend([["Highest incident score", max(scores)], ["Average incident score", round(sum(scores)/len(scores), 1)]])
        if kind == "incident" and selected and cfg["type"] == "risk":
            top = selected[0]["values"]
            if top[2] is not None:
                findings.append(f"Highest incident risk: {top[0]} ({top[2]}/100, {top[3]}).")
        counts = Counter(r["severity"] or "unknown" for r in selected)
        summary.append([LABELS[kind], len(selected)])
        charts.append(dict(title=LABELS[kind] + (" by criticality" if kind == "asset" else " by severity or risk level"),
                           kind="bar", items=sorted(counts.items())))
        if kind != "asset":
            trend = Counter(r["time"][:10] for r in selected)
            charts.append(dict(title=LABELS[kind] + " by date", kind="line", items=sorted(trend.items())))
        tables.append(dict(title=LABELS[kind], cols=COLUMNS[kind], rows=[r["values"] for r in selected]))
    return dict(records=sum(len(t["rows"]) for t in tables), summary=summary, charts=charts, tables=tables,
                findings=findings, guidance=[], notes=[])


def register_reports(app, db, get_current_user_id):
    with db.session() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS report_snapshots (
            id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, payload TEXT NOT NULL)""")

    @app.route("/api/reports", methods=["GET", "POST"])
    @require_auth
    def reports():
        uid = get_current_user_id()
        if uid is None:
            return jsonify(error="Sign in again."), 401
        with db.session() as conn:
            if request.method == "GET":
                history = []
                for row in conn.execute("SELECT id,payload FROM report_snapshots WHERE user_id=? ORDER BY id DESC", (uid,)):
                    history.append(dict(json.loads(row["payload"]), id=f"RPT-{row['id']}"))
                return jsonify(history)
            data = request.get_json(silent=True)
            if not isinstance(data, dict) or not isinstance(data.get("cfg"), dict):
                return jsonify(error="Missing report settings."), 400
            cfg = {k: str(data["cfg"].get(k, "")) for k in ("type", "start", "end", "sev", "status", "asset")}
            try:
                start, end = (date.fromisoformat(cfg[k]) for k in ("start", "end"))
                valid = start <= end and cfg["type"] in CATEGORIES
            except ValueError:
                valid = False
            name = str(data.get("name", "")).strip()
            if not valid or not 3 <= len(name) <= 80 or data.get("format") not in ("pdf", "csv", "json"):
                return jsonify(error="Check the report name, dates, type and format."), 400
            conn.execute("BEGIN")
            body = build(read_source(conn, uid), cfg)
            username = conn.execute("SELECT username FROM users WHERE id=?", (uid,)).fetchone()["username"]
            report = dict(name=name, type=cfg["type"], cfg=cfg, format=data["format"], by=username,
                          generatedAt=datetime.now(timezone.utc).isoformat(), status="completed", body=body)
            cur = conn.execute("INSERT INTO report_snapshots(user_id,payload) VALUES (?,?)", (uid, json.dumps(report)))
            return jsonify(dict(report, id=f"RPT-{cur.lastrowid}")), 201

    @app.get("/api/reports/analytics")
    @require_auth
    def analytics():
        uid = get_current_user_id()
        if uid is None:
            return jsonify(error="Sign in again."), 401
        with db.session() as conn:
            conn.execute("BEGIN")
            source = read_source(conn, uid)
        dates = [r["time"][:10] for rows in source.values() for r in rows if r["time"]]
        first = min(dates, default=datetime.now(timezone.utc).date().isoformat())
        cfg = {k: request.args.get(k, "") for k in ("start", "end")}
        cfg.update(sev="", status="", asset="")
        cfg["start"] = cfg["start"] or first
        cfg["end"] = cfg["end"] or datetime.now(timezone.utc).date().isoformat()
        bodies = {k: build(source, dict(cfg, type=k)) for k in ("overview", "threat", "risk", "incident")}
        incidents = bodies["incident"]["tables"][0]["rows"]
        return jsonify(bodies=bodies, first=first, start=cfg["start"], end=cfg["end"],
                       assets=[[r["values"][1], r["values"][3]] for r in source["asset"]],
                       openCount=sum(r[4] == "open" for r in incidents), criticalCount=sum(r[3] == "critical" for r in incidents))

    @app.delete("/api/reports/<int:report_id>")
    @require_auth
    def delete_report(report_id):
        uid = get_current_user_id()
        if uid is None:
            return jsonify(error="Sign in again."), 401
        with db.session() as conn:
            cur = conn.execute("DELETE FROM report_snapshots WHERE id=? AND user_id=?", (report_id, uid))
            if not cur.rowcount:
                return jsonify(error="Report unavailable."), 404
        return "", 204
