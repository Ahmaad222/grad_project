from core.event_bus import threat_queue
from config import ENABLE_ACTIVE_CONTAINMENT, INTERFACE
from prevention.containment_engine import ContainmentEngine
from monitoring.sniffer import clients_map


class ResponseEngine:

    def start(self):

        containment = ContainmentEngine(INTERFACE)

        while True:
            threat = threat_queue.get()

            print("\n🚨 CONFIRMED THREAT 🚨")
            print(f"SSID: {threat['event']['ssid']}")
            print(f"BSSID: {threat['event']['bssid']}")
            print(f"Score: {threat['score']}")
            print("Reasons:")
            for r in threat["reasons"]:
                print(f" - {r}")
            print("\n")

            if ENABLE_ACTIVE_CONTAINMENT:

                clients = clients_map.get(
                    threat['event']['bssid'], set()
                )

                if clients:
                    containment.contain(
                        threat['event']['bssid'],
                        clients,
                        threat['event']['channel']
                    )
                else:
                    print("[Containment] No clients found.")