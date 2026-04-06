from flask import Flask, render_template, jsonify, request, Response
from wifi_scanner import scan_wifi
from trust_analyzer import analyze_trust
from portal_checker import check_portal
from packet_monitor import start_monitoring, stop_monitoring, get_alerts, clear_alerts
from logger import log_event
import json
import os
import subprocess
import tempfile

app = Flask(__name__, static_folder="static", template_folder="templates")

networks_cache = []


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan")
def scan():
    global networks_cache
    try:
        networks = scan_wifi()
        result = []

        for idx, net in enumerate(networks):
            ssid = net.get("ssid", "").strip()
            if not ssid:
                continue

            status, score, reason = analyze_trust(net)
            result.append({
                "id": idx,
                "ssid": ssid,
                "security": net.get("security", "Unknown"),
                "signal": net.get("signal", "Unknown"),
                "status": status,
                "score": score,
                "reason": reason,
            })

        networks_cache = networks
        log_event(f"Scanned {len(result)} networks")
        return jsonify(result)
    except Exception as exc:
        log_event(f"Scan failed: {exc}")
        return jsonify({"error": "Failed to scan networks"}), 500


@app.route("/connect/<int:index>", methods=["POST"])
def connect(index):
    try:
        if index < 0 or index >= len(networks_cache):
            return jsonify({"error": "Invalid network index"}), 400

        net = networks_cache[index]
        ssid = net.get("ssid", "Unknown")
        security = net.get("security", "Unknown")

        status, score, reason = analyze_trust(net)
        data = request.get_json(silent=True) or {}
        password = data.get("password")

        if "open" not in security.lower() and not password:
            return jsonify({"error": "Password required for encrypted network"}), 400

        log_event(f"Connecting to {ssid} (security={security})")
        connection_result = connect_to_wifi(ssid, password, security)

        if not connection_result["success"]:
            log_event(f"Failed to connect to {ssid}: {connection_result['error']}")
            return jsonify({"error": connection_result["error"]}), 500

        portal_status = check_portal()
        start_monitoring()

        message = f"Connected to {ssid} | Portal: {portal_status}"
        log_event(message)
        return jsonify({"message": message, "portal": portal_status})

    except Exception as exc:
        log_event(f"Connect failed: {exc}")
        return jsonify({"error": "Connection failed"}), 500


@app.route("/api/alerts")
def alerts_stream():
    def generate():
        last_alert_count = 0
        while True:
            try:
                current_alerts = get_alerts()
                if len(current_alerts) > last_alert_count:
                    for alert in current_alerts[last_alert_count:]:
                        yield f"data: {json.dumps(alert)}\n\n"
                    last_alert_count = len(current_alerts)
                time.sleep(1)
            except GeneratorExit:
                break
            except Exception as e:
                log_event(f"SSE error: {e}")
                break

    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/stop_monitoring", methods=["POST"])
def api_stop_monitoring():
    try:
        stop_monitoring()
        log_event("Monitoring stopped via API")
        return jsonify({"status": "stopped"})
    except Exception as exc:
        log_event(f"Stop monitoring failed: {exc}")
        return jsonify({"error": "Failed to stop monitoring"}), 500


@app.route("/api/clear_alerts", methods=["POST"])
def api_clear_alerts():
    try:
        clear_alerts()
        return jsonify({"status": "cleared"})
    except Exception as exc:
        log_event(f"Clear alerts failed: {exc}")
        return jsonify({"error": "Failed to clear alerts"}), 500


def connect_to_wifi(ssid, password=None, security="Open"):
    security_lower = security.lower()
    profile_name = ssid.replace('"', '')

    if "open" in security_lower or not password:
        auth = "open"
        encryption = "none"
    elif "wpa3" in security_lower:
        auth = "WPA2PSK"
        encryption = "AES"
    elif "wpa2" in security_lower:
        auth = "WPA2PSK"
        encryption = "AES"
    elif "wpa" in security_lower:
        auth = "WPAPSK"
        encryption = "TKIP"
    elif "wep" in security_lower:
        auth = "open"
        encryption = "WEP"
    else:
        auth = "WPA2PSK"
        encryption = "AES"

    profile_xml = f'''<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{profile_name}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>{auth}</authentication>
                <encryption>{encryption}</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password or ''}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>'''

    profile_file = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False, encoding='utf-8') as temp_file:
            temp_file.write(profile_xml)
            profile_file = temp_file.name

        add_cmd = f'netsh wlan add profile filename="{profile_file}"'
        add_result = subprocess.run(add_cmd, shell=True, capture_output=True, text=True, timeout=15)
        if add_result.returncode != 0:
            error_msg = add_result.stderr.strip() or "Failed to add Wi-Fi profile"
            return {"success": False, "error": error_msg}

        connect_cmd = f'netsh wlan connect name="{profile_name}" ssid="{ssid}"'
        connect_result = subprocess.run(connect_cmd, shell=True, capture_output=True, text=True, timeout=30)
        if connect_result.returncode == 0:
            return {"success": True, "error": None}

        error_msg = connect_result.stderr.strip() or "Connection failed"
        return {"success": False, "error": error_msg}

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Connection timeout"}
    except Exception as exc:
        return {"success": False, "error": str(exc)}
    finally:
        if profile_file and os.path.exists(profile_file):
            try:
                os.remove(profile_file)
            except Exception:
                pass


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
