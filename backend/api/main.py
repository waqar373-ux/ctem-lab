from fastapi import FastAPI, Body
import psycopg, json
from typing import Dict
from datetime import datetime

app = FastAPI(title="CTEM MVP API")

# --- Database Connection Helper ---
def db():
    return psycopg.connect("dbname=ctem user=ctem password=ctem host=db")

# --- Healthcheck ---
@app.get("/health")
def health():
    with db() as conn, conn.cursor() as cur:
        cur.execute("select 1")
        cur.fetchone()
    return {"ok": True}

# --- List Assets ---
@app.get("/assets")
def list_assets():
    with db() as conn, conn.cursor() as cur:
        cur.execute("select id, hostname, ip, os, last_seen from assets order by last_seen desc")
        rows = cur.fetchall()
        return [
            {
                "id": r[0],
                "hostname": r[1],
                "ip": r[2],
                "os": r[3],
                "last_seen": r[4].isoformat()
            } for r in rows
        ]

# --- List Findings ---
@app.get("/findings")
def list_findings(limit: int = 50):
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "select id, type, reference_id, risk, status from findings order by created_at desc limit %s",
            (limit,)
        )
        rows = cur.fetchall()
        return [
            {
                "id": r[0],
                "type": r[1],
                "reference_id": r[2],
                "risk": float(r[3]) if r[3] else None,
                "status": r[4]
            } for r in rows
        ]

# --- Ingest Asset & Packages (simulate osquery) ---
@app.post("/ingest/osquery")
def ingest_osquery(payload: Dict = Body(...)):
    with db() as conn, conn.cursor() as cur:
        host = payload.get("host", {})
        hostname = host.get("hostname")
        ip = host.get("ip")
        osname = host.get("os", "Linux")

        # Insert or update asset
        cur.execute("""
            insert into assets(hostname, ip, os, last_seen)
            values(%s, %s, %s, now())
            on conflict (hostname)
            do update set ip = excluded.ip, os = excluded.os, last_seen = now()
        """, (hostname, ip, osname))

        cur.execute("select id from assets where hostname=%s", (hostname,))
        asset_id = cur.fetchone()[0]

        # Insert packages
        for p in payload.get("packages", []):
            cur.execute("""
                insert into packages(asset_id, name, version, cpe)
                values(%s, %s, %s, %s)
            """, (asset_id, p.get("name"), p.get("version"), p.get("cpe")))

    return {"ingested": True, "at": datetime.utcnow().isoformat()}

# --- Create Action ---
@app.post("/actions")
def create_action(body: Dict = Body(...)):
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            insert into actions(finding_id, playbook, params_json)
            values (%s, %s, %s) returning id
        """, (body["finding_id"], body["playbook"], json.dumps(body.get("params", {}))))
        aid = cur.fetchone()[0]

    return {"id": aid, "status": "pending"}
