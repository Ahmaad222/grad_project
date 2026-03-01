# prevention/response_engine.py

from core.event_bus import threat_queue


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