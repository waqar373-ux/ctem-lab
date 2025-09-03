import json, subprocess, requests, socket, platform

def q(sql):
    return json.loads(subprocess.check_output(["osqueryi","--json",sql]))

# Get host IP from osquery
host_ip = q("select address from interface_addresses where address like '%.%' limit 1;")[0]["address"]

# Build payload for API
payload = {
    "host": {
        "hostname": socket.gethostname(),
        "ip": host_ip,
        "os": platform.platform()
    },
    "packages": q("select name, version from deb_packages limit 2000;")
}

print("sending", len(payload["packages"]), "packages")

# Send payload to your FastAPI ingestion endpoint
r = requests.post("http://127.0.0.1:8000/ingest/osquery", json=payload, timeout=30)
print(r.status_code, r.text)
