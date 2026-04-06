"""Trust analyzer module for classifying Wi-Fi networks."""


def analyze_trust(network):
    security = network.get('security', 'Unknown').lower()
    signal = network.get('signal', '0%')
    score = 0
    reason = 'Unknown security profile'

    if 'open' in security or 'none' in security:
        status = 'RISKY'
        score = 20
        reason = 'Open network with no encryption'
    elif 'wpa3' in security:
        status = 'SAFE'
        score = 95
        reason = 'Modern WPA3 encryption'
    elif 'wpa2' in security:
        status = 'SAFE'
        score = 85
        reason = 'Strong WPA2 encryption'
    elif 'wpa' in security:
        status = 'MODERATE'
        score = 65
        reason = 'Legacy WPA encryption'
    elif 'wep' in security:
        status = 'RISKY'
        score = 30
        reason = 'Weak WEP encryption'
    else:
        status = 'MODERATE'
        score = 55
        reason = 'Unknown security mode'

    try:
        signal_value = int(signal.replace('%', '').strip())
    except Exception:
        signal_value = None

    if signal_value is not None:
        if signal_value < 30:
            score = max(score - 15, 0)
            reason += ' + weak signal'
        elif signal_value > 70:
            score = min(score + 5, 100)

    if score >= 80:
        status = 'SAFE'
    elif score >= 50:
        status = 'MODERATE'
    else:
        status = 'RISKY'

    return status, score, reason
