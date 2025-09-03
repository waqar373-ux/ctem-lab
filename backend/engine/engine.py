import psycopg, re

DB="dbname=ctem user=ctem password=ctem host=db"

def naive_match(pkg_name, summary):
    """Return True if package name is found in CVE summary text."""
    return re.search(rf"\b{re.escape(pkg_name)}\b", (summary or "").lower()) is not None

with psycopg.connect(DB) as conn, conn.cursor() as cur:
    # Get all packages linked to assets
    cur.execute("select a.id, p.name from assets a join packages p on a.id=p.asset_id")
    pkgs = cur.fetchall()

    # Get all CVEs
    cur.execute("select cve_id, cvss, summary from vulns where summary is not null")
    vulns = cur.fetchall()

    count = 0
    for asset_id, name in pkgs:
        n = name.lower()
        for cve_id, cvss, summary in vulns:
            if naive_match(n, summary.lower()):
                risk = float(cvss) if cvss is not None else 4.0
                cur.execute(
                    """insert into findings(asset_id, source, type, reference_id, risk)
                       values (%s,'correlator','vuln',%s,%s)
                       on conflict do nothing""",
                    (asset_id, cve_id, risk),
                )
                count += 1
    conn.commit()

print("correlation complete ✅", count, "findings created")
