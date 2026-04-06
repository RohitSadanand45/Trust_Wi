import subprocess
import re

command = "netsh wlan show networks mode=Bssid"
result = subprocess.check_output(command, shell=True).decode()

print("="*60)
print("DETAILED PARSING DEBUG")
print("="*60)

networks = []
ssid = None
security = None

lines = result.split("\n")
print(f"Total lines: {len(lines)}\n")

for i, line in enumerate(lines):
    stripped = line.strip()
    
    # Match SSID lines with regex: "SSID 1 : NetworkName" (but NOT BSSID)
    if re.match(r"^SSID\s+\d+\s*:", stripped):
        print(f"Line {i}: SSID line found: {repr(stripped)}")
        parts = stripped.split(":", 1)
        extracted_ssid = parts[1].strip() if len(parts) == 2 else None
        print(f"  -> Extracted: {repr(extracted_ssid)}")
        ssid = extracted_ssid
    
    # Show all Authentication lines
    elif "Authentication" in stripped and ":" in stripped:
        print(f"Line {i}: Auth line found: {repr(stripped)}")
        parts = stripped.split(":", 1)
        extracted_security = parts[1].strip() if len(parts) == 2 else None
        print(f"  -> Extracted: {repr(extracted_security)}")
        security = extracted_security
        
        if ssid and security:
            print(f"  -> ADDING NETWORK: {repr(ssid)} / {repr(security)}")
            networks.append({"ssid": ssid, "security": security})
            ssid = None
            security = None
        print()

print("="*60)
print(f"FINAL RESULT: {len(networks)} networks parsed")
for net in networks:
    print(f"  - {net['ssid']}: {net['security']}")
