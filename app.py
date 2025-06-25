from flask import Flask, render_template, request, jsonify
import json, os, requests, re, webbrowser
import datetime


app = Flask(__name__)

@app.route("/")
def index():
    try:
        with open("../reports/scan_log.json") as f:
            logs = [json.loads(line) for line in f.readlines()]
    except FileNotFoundError:
        logs = []

    try:
        with open("../reports/lookup_log.json") as f:
            lookups = [json.loads(line) for line in f.readlines()]
    except FileNotFoundError:
        lookups = []

    # ✅ Read tags
    tag_map = {}
    try:
        with open("../reports/tags.json") as f:
            for line in f:
                tag_entry = json.loads(line)
                tag_map[tag_entry["target"]] = tag_entry["tag"]
    except FileNotFoundError:
        pass

    # ✅ Add tag info into lookup records
    for lookup in lookups:
        target = lookup.get("target")
        if target in tag_map:
            lookup["tag"] = tag_map[target]
        else:
            lookup["tag"] = "N/A"

    vuln_counts = {"XSS": 0, "SQLi": 0, "CSRF": 0}
    for log in logs:
        if log['type'] in vuln_counts:
            vuln_counts[log['type']] += 1

    return render_template("index.html", logs=logs, lookups=lookups, vuln_counts=vuln_counts)


@app.route("/lookup", methods=["POST"])
def lookup():
    raw = request.form.get("target").strip()
    domain = raw.replace("https://", "").replace("http://", "").strip("/")
    target = domain
    result = {
        "target": target,
        "timestamp": datetime.datetime.now().isoformat()  # ✅ Add timestamp here
    }

    VT_API_KEY = "2811e469b09dd55fdfaafc287d30f1075f3450edef8bcec5e487a8b2aae63af6"
    is_ip = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target)

    try:
        # VirusTotal Lookup
        vt_headers = {"x-apikey": VT_API_KEY}
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}" if is_ip else f"https://www.virustotal.com/api/v3/domains/{target}"
        vt_response = requests.get(vt_url, headers=vt_headers)
        result['virustotal'] = vt_response.json().get("data", {}) if vt_response.ok else {"error": f"VT error {vt_response.status_code}"}
        if "attributes" not in result["virustotal"]:
            result["virustotal"]["attributes"] = {}

        # RDAP Lookup for WHOIS-style info (only if IP)
        if is_ip:
            rdap_response = requests.get(f"https://rdap.apnic.net/ip/{target}")
            result['rdap'] = rdap_response.json() if rdap_response.ok else {"error": f"RDAP error {rdap_response.status_code}"}

    except Exception as e:
        result['error'] = str(e)

    os.makedirs("../reports", exist_ok=True)
    with open("../reports/lookup_log.json", "a") as f:
        f.write(json.dumps(result) + "\n")

    return jsonify(result)


@app.route("/save_tag", methods=["POST"])
def save_tag():
    try:
        data = request.get_json()
        tag_entry = {
            "target": data.get("target"),
            "tag": data.get("tag"),
            "timestamp": datetime.datetime.now().isoformat()
        }
        os.makedirs("../reports", exist_ok=True)
        with open("../reports/tags.json", "a") as f:
            f.write(json.dumps(tag_entry) + "\n")
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, error=str(e))


@app.route("/delete_log", methods=["POST"])
def delete_log():
    index = int(request.form.get("index"))
    try:
        with open("../reports/scan_log.json") as f:
            logs = [json.loads(line) for line in f.readlines()]
        if 0 <= index < len(logs):
            logs.pop(index)
            with open("../reports/scan_log.json", "w") as f:
                for log in logs:
                    f.write(json.dumps(log) + "\n")
            return jsonify(success=True)
        return jsonify(success=False, error="Invalid index")
    except Exception as e:
        return jsonify(success=False, error=str(e))
        

if __name__ == "__main__":
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        webbrowser.open("http://vulnscope.local")
    app.run(host="0.0.0.0", port=80, debug=True)
