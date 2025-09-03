import psycopg, subprocess, json, time, shlex

DB = "dbname=ctem user=ctem password=ctem host=db"

def run_playbook(playbook, params):
    extra_vars = []
    for k, v in (params or {}).items():
        extra_vars.append(f"{k}={v}")
    ev = " ".join(extra_vars)

    # This path is now updated to look inside the mounted directory
    cmd = f"ansible-playbook -i /app/playbooks/hosts.ini /app/playbooks/{playbook}.yml"
    if ev:
        cmd += f" -e {shlex.quote(ev)}"

    print("Running:", cmd, flush=True)
    out = subprocess.check_output(["sh", "-lc", cmd], text=True)
    return out

while True:
    with psycopg.connect(DB) as conn, conn.cursor() as cur:
        cur.execute("""select id, playbook, params_json
                       from actions where status='pending'
                       order by id asc limit 1 for update skip locked""")
        row = cur.fetchone()
        if not row:
            time.sleep(2)
            continue

        aid, playbook, params = row
        cur.execute("update actions set status='running', started_at=now() where id=%s",(aid,))
        conn.commit()

        try:
            if playbook not in ("block_ip","patch_package"):
                raise ValueError(f"Unknown playbook: {playbook}")
            out = run_playbook(playbook, params)
            status = 'done'
        except Exception as e:
            out = f"ERROR: {e}"
            status = 'failed'

        with conn.cursor() as cur2:
            cur2.execute("update actions set status=%s, finished_at=now(), log=%s where id=%s", (status, out, aid))
            cur2.execute("insert into audit_log(actor,action,target,meta) values('admin','remediate',%s,%s)",
                           (playbook, json.dumps(params or {})))
            conn.commit()
