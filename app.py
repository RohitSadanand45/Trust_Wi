from flask import Flask, render_template, jsonify, request, Response
from wifi_scanner import scan_wifi
from trust_analyzer import analyze_trust
from portal_checker import check_portal
from packet_monitor import start_monitoring, stop_monitoring, get_alerts, clear_alerts
from logger import log_event
import threading
import time
import json

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

        for net in networks:
            ssid = net.get("ssid", "").strip()
            # Skip empty SSIDs
            if not ssid:
                continue
                
            status, score, reason = analyze_trust(net)
            result.append({
                "ssid": ssid,
                "security": net.get("security", "Unknown"),
                "status": status
            })

        networks_cache = networks
        log_event(f"Scanned {len(result)} networks")
        return jsonify(result)
    except Exception as exc:
        log_event(f"Scan failed: {exc}")
        return jsonify({"error": "Failed to scan networks"}), 500

@app.route("/connect/<int:index>", methods=["GET", "POST"])
def connect(index):
    try:
        if index < 0 or index >= len(networks_cache):
            return jsonify({"error": "Invalid network index"}), 400

        net = networks_cache[index]
        ssid = net.get("ssid", "Unknown")
        security = net.get("security", "Unknown")

        log_event(f"Attempting to connect to {ssid}")

        # Check if network requires password
        from trust_analyzer import analyze_trust
        status, score, reason = analyze_trust(net)
        
        password = None
        if request.method == "POST":
            data = request.get_json()
            password = data.get("password") if data else None

        # For encrypted networks, require password
        if (status == "SAFE" or status == "MODERATE") and not password:
            return jsonify({"error": "Password required for encrypted network"}), 400

        # Attempt to connect to the network
        connection_result = connect_to_wifi(ssid, password, security)
        
        if connection_result["success"]:
            # Check portal
            portal_status = check_portal()

            # Start monitoring in background (continuous)
            start_monitoring()

            message = f"Successfully connected to {ssid} | Portal: {portal_status}"
            log_event(message)
            return jsonify({"message": message})
        else:
            log_event(f"Failed to connect to {ssid}: {connection_result['error']}")
            return jsonify({"error": connection_result["error"]}), 500

    except Exception as exc:
        log_event(f"Connect failed: {exc}")
        return jsonify({"error": "Connection failed"}), 500

@app.route("/api/alerts")
def alerts_stream():
    """Server-Sent Events endpoint for real-time alerts"""
    def generate():
        last_alert_count = 0
        while True:
            try:
                current_alerts = get_alerts()
                if len(current_alerts) > last_alert_count:
                    # Send new alerts
                    new_alerts = current_alerts[last_alert_count:]
                    for alert in new_alerts:
                        yield f"data: {json.dumps(alert)}\n\n"
                    last_alert_count = len(current_alerts)
                time.sleep(1)  # Check for new alerts every second
            except Exception as e:
                print(f"SSE error: {e}")
                break
    
    return Response(generate(), mimetype="text/event-stream")

@app.route("/api/stop_monitoring", methods=["POST"])
def api_stop_monitoring():
    """Stop monitoring"""
    try:
        stop_monitoring()
        log_event("Monitoring stopped via API")
        return jsonify({"status": "stopped"})
    except Exception as exc:
        log_event(f"Stop monitoring failed: {exc}")
        return jsonify({"error": "Failed to stop monitoring"}), 500

@app.route("/api/clear_alerts", methods=["POST"])
def api_clear_alerts():
    """Clear all alerts"""
    try:
        clear_alerts()
        return jsonify({"status": "cleared"})
    except Exception as exc:
        return jsonify({"error": "Failed to clear alerts"}), 500


def connect_to_wifi(ssid, password=None, security="Open"):
    """
    Attempt to connect to a WiFi network using netsh commands.
    Returns: {"success": bool, "error": str}
    """
    try:
        import subprocess
        
        # For open networks
        if "Open" in security or not password:
            print(f"Attempting to connect to open network: {ssid}")
            cmd = f'netsh wlan connect name="{ssid}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=30)
            print(f"Netsh result: {result.returncode}")
            if result.returncode == 0:
                return {"success": True, "error": None}
            else:
                error_msg = result.stderr.strip() if result.stderr else "Connection command failed"
                return {"success": False, "error": error_msg}
        
        # For encrypted networks, create a temporary profile
        else:
            print(f"Attempting to connect to encrypted network: {ssid}")
            # Create XML profile for the network
            profile_xml = f'''<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
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
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>'''

            # Write profile to temp file
            import tempfile
            import os
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False, encoding='utf-8') as f:
                f.write(profile_xml)
                profile_path = f.name
            
            try:
                # Add the profile
                print("Adding WiFi profile...")
                add_cmd = f'netsh wlan add profile filename="{profile_path}"'
                add_result = subprocess.run(add_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=10)
                print(f"Add profile result: {add_result.returncode}")
                
                if add_result.returncode != 0:
                    error_msg = add_result.stderr.strip() if add_result.stderr else "Failed to add WiFi profile"
                    return {"success": False, "error": error_msg}
                
                # Connect to the network
                print("Connecting to network...")
                connect_cmd = f'netsh wlan connect name="{ssid}"'
                connect_result = subprocess.run(connect_cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=30)
                print(f"Connect result: {connect_result.returncode}")
                
                if connect_result.returncode == 0:
                    return {"success": True, "error": None}
                else:
                    error_msg = connect_result.stderr.strip() if connect_result.stderr else "Connection failed"
                    return {"success": False, "error": error_msg}
                    
            finally:
                # Clean up temp file
                try:
                    os.unlink(profile_path)
                except:
                    pass
                    
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Connection timeout - network may be out of range"}
    except Exception as e:
        return {"success": False, "error": f"Connection error: {str(e)}"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)