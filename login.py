# app.py
from flask import Flask, request, jsonify
from datetime import datetime
import csv, os

app = Flask(__name__)
LOG_FILE = "login_log.csv"
FIELDNAMES = ["ts","user","device","ip","country","success"]


if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="") as f:
        csv.DictWriter(f, fieldnames=FIELDNAMES).writeheader()

def client_ip(req: request) -> str:
    fwd = req.headers.get("X-Forwarded-For")
    if fwd:  # may contain "ip1, ip2, ..."
        return fwd.split(",")[0].strip()
    return req.remote_addr or "127.0.0.1"

@app.post("/login")
def login():
    data = request.get_json(force=True, silent=True) or {}
    
    user    = str(data.get("user", "")).strip()
    device  = str(data.get("device", "")).strip()
    country = str(data.get("country", "DE")).strip()  # default DE
    success = int(bool(data.get("success", 1)))       # default successful

    if not user or not device:
        return jsonify({"ok": False, "error": "user and device are required"}), 400

    row = {
        "ts": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "user": user,
        "device": device,
        "ip": client_ip(request),           # 127.0.0.1
        "country": country,
        "success": success,                 # 1 = success, 0 = failure
    }

    with open(LOG_FILE, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDNAMES)
        w.writerow(row)

    return jsonify({"ok": True, "logged": row})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)  # bind explicitly to localhost
