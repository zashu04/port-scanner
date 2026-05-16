from flask import Flask, render_template, request, jsonify
from scanner import scan_host, parse_ports, PRESETS

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data    = request.get_json(silent=True) or {}
    host    = data.get("host", "").strip()
    preset  = data.get("preset", "common")
    custom  = data.get("custom_ports", "").strip()
    timeout = float(data.get("timeout", 0.5))

    if not host:
        return jsonify({"error": "No host provided."}), 400

    timeout = max(0.2, min(timeout, 3.0))

    if preset == "custom":
        if not custom:
            return jsonify({"error": "No ports specified for custom scan."}), 400
        try:
            ports = parse_ports(custom)
        except ValueError:
            return jsonify({"error": "Invalid port specification. Use formats like: 22,80,443 or 1-1024"}), 400
    else:
        ports = PRESETS.get(preset, PRESETS["common"])

    if not ports:
        return jsonify({"error": "No valid ports to scan."}), 400

    result = scan_host(host, ports, timeout)
    return jsonify(result)


@app.route("/presets", methods=["GET"])
def presets():
    return jsonify({k: len(v) for k, v in PRESETS.items()})


if __name__ == "__main__":
    app.run(debug=True, port=5002)
