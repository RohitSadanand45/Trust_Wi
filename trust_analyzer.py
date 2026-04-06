def analyze_trust(network):
    """
    Analyzes network security status for public WiFi scenarios.
    Returns: (status, risk_score, reason)
    - SAFE: WPA2/WPA3 encrypted networks (home/office WiFi)
    - MODERATE: Weak encryption like WEP
    - RISKY: Open/unencrypted networks (public free WiFi hotspots)
    """
    security = network["security"]

    if "Open" in security:
        return "RISKY", 90, "No encryption - Public open network"

    elif "WPA2" in security or "WPA3" in security:
        return "SAFE", 20, "Strong encryption - Secure"

    else:
        return "MODERATE", 50, "Weak/Unknown encryption type"