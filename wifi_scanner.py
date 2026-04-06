import subprocess
import re


def scan_wifi():
    """Scan Wi-Fi networks using Windows netsh and return structured network data."""
    command = "netsh wlan show networks mode=Bssid"
    try:
        result = subprocess.check_output(
            command,
            shell=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
    except subprocess.CalledProcessError:
        return []
    except Exception:
        return []

    networks = []
    current = None

    for raw_line in result.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        ssid_match = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line)
        if ssid_match:
            if current and current.get("ssid"):
                networks.append(current)

            current = {
                "ssid": ssid_match.group(1).strip(),
                "signal": "Unknown",
                "security": "Unknown",
            }
            continue

        if current is None:
            continue

        if line.startswith("Signal") and ":" in line:
            current["signal"] = line.split(":", 1)[1].strip()
            continue

        if line.startswith("Authentication") and ":" in line:
            current["security"] = line.split(":", 1)[1].strip()
            continue

    if current and current.get("ssid"):
        networks.append(current)

    unique = []
    seen = set()
    for net in networks:
        key = (net["ssid"], net["security"], net["signal"])
        if key not in seen:
            seen.add(key)
            unique.append(net)

    return unique
