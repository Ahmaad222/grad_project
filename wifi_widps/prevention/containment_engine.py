# prevention/containment_engine.py

class ContainmentEngine:

    def __init__(self, iface):
        self.iface = iface

    def contain(self, bssid, clients):
        print(f"[Containment] Targeting {bssid}")

        for client in clients:
            self.deauth_pair(bssid, client)

    def deauth_pair(self, bssid, client):
        # هنا فقط تبني وتبعت Deauth frame
        # (RadioTap + Dot11 + Dot11Deauth)
        pass