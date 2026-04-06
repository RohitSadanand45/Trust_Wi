from wifi_scanner import scan_wifi
from trust_analyzer import analyze_trust
from portal_checker import check_portal
from packet_monitor import start_monitoring
from logger import log_event

def main():
    print("🔐 Public Wi-Fi Trust Analyzer\n")

    # Step 1: Scan Wi-Fi
    networks = scan_wifi()

    print("📊 Available Networks:\n")

    for i, net in enumerate(networks):
        status, score, reason = analyze_trust(net)

        print(f"{i+1}. {net['ssid']}")
        print(f"   Security: {net['security']}")
        print(f"   Trust: {status} ({reason})\n")

    # Step 2: User selects network
    choice = int(input("Select network number: ")) - 1
    selected = networks[choice]

    print(f"\n🔗 Connected to: {selected['ssid']}")

    # Step 3: Portal Check
    portal_status = check_portal()
    log_event(f"Portal status: {portal_status}")

    # Step 4: Continuous Monitoring
    start_monitoring()


if __name__ == "__main__":
    main()