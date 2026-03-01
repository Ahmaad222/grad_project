# prevention/response_engine.py

from core.event_bus import threat_queue
from config import ENABLE_ACTIVE_CONTAINMENT
from prevention.containment_engine import ContainmentEngine
from config import INTERFACE
from monitoring.sniffer import clients_map

class ResponseEngine:

    def start(self):
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

            #هجوم deauth
            if ENABLE_ACTIVE_CONTAINMENT:
                clients = clients_map.get(threat['event']['bssid'], set())

                if clients:
                  containment = ContainmentEngine(INTERFACE)
                  containment.contain(
                  threat['event']['bssid'],
                  clients
        )
      