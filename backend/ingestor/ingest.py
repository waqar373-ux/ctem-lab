import httpx, psycopg, datetime, json

DB = "dbname=ctem user=ctem password=ctem host=db"

def upsert_vuln(cur, cve_id, cvss, summary, published, cpe_matches):
    cur.execute(
        """insert into vulns(cve_id,cvss,summary,published,cpe_matches)
           values (%s,%s,%s,%s,%s)
           on conflict (cve_id) do update set cvss=excluded.cvss,
           summary=excluded.summary, published=excluded.published,
           cpe_matches=excluded.cpe_matches""",
        (cve_id, cvss, summary, published, json.dumps(cpe_matches))
    )

with psycopg.connect(DB) as conn, conn.cursor() as cur, httpx.Client(timeout=90) as http:
    # --- CISA KEV feed ---
    kev = http.get(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    ).json()
    kev_ids = {v["cveID"] for v in kev.get("vulnerabilities", [])}
    print(f"Loaded {len(kev_ids)} KEV CVEs")

    # --- NVD: fetch last 7 days ---
    today = datetime.datetime.now(datetime.UTC)
    week_ago = today - datetime.timedelta(days=7)

    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={week_ago.strftime('%Y-%m-%dT00:00:00.000')}"
        f"&pubEndDate={today.strftime('%Y-%m-%dT00:00:00.000')}"
        "&resultsPerPage=200"
    )

    r = http.get(url)
    if r.status_code != 200:
        raise SystemExit(f"NVD API error {r.status_code}: {r.text}")

    vulns = r.json().get("vulnerabilities", [])
    print(f"Fetched {len(vulns)} CVEs from NVD")

    for v in vulns:
        cve = v["cve"]
        cve_id = cve["id"]
        summary = cve.get("descriptions", [{"value": ""}])[0]["value"]
        published = v.get("published")

        cvss = None
        metrics = cve.get("metrics", {})
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if k in metrics:
                cvss = metrics[k][0]["cvssData"]["baseScore"]
                break

        cfg = cve.get("configurations", {})
        upsert_vuln(cur, cve_id, cvss, summary, published, cfg)

    conn.commit()

print("Ingestion complete ✅")
