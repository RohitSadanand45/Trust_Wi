from wifi_scanner import scan_wifi
from trust_analyzer import analyze_trust
from portal_checker import check_portal
from app import connect_to_wifi
from packet_monitor import start_monitoring
from logger import log_event


def safe_int_input(prompt, minimum, maximum):
    while True:
        try:
            value = int(input(prompt).strip())
            if minimum <= value <= maximum:
                return value
            print(f"Please enter a number between {minimum} and {maximum}.")
        except ValueError:
            print("Invalid input. Please enter a number.")


def main():
    print("🔐 Smart Public Wi-Fi Trust Analyzer with Real-Time Intrusion Detection\n")

    networks = scan_wifi()
    if not networks:
        print("No Wi-Fi networks detected. Please ensure your wireless adapter is enabled.")
        return

    print("📊 Available Networks:\n")
    for index, net in enumerate(networks, start=1):
        status, score, reason = analyze_trust(net)
        print(f"{index}. {net['ssid']}")
        print(f"   Security: {net['security']}")
        print(f"   Signal: {net.get('signal', 'Unknown')}")
        print(f"   Trust: {status} ({score} / 100) - {reason}\n")

    choice = safe_int_input("Select network number: ", 1, len(networks)) - 1
    selected = networks[choice]

    print(f"\n🔗 Selected network: {selected['ssid']}")
    password = None
    if "open" not in selected["security"].lower():
        password = input("Enter Wi-Fi password (leave empty if not required): ").strip() or None

    connect_result = connect_to_wifi(
        selected["ssid"], password=password, security=selected["security"]
    )

    if not connect_result["success"]:
        print(f"Connection failed: {connect_result['error']}")
        log_event(f"Connection failed: {connect_result['error']}")
        return

    portal_status = check_portal()
    log_event(f"Connected to {selected['ssid']} | Portal status: {portal_status}")
    print(f"Portal check result: {portal_status}")

    print("\nStarting packet monitoring. Press Ctrl+C to stop.")
    start_monitoring()


if __name__ == "__main__":
    main()