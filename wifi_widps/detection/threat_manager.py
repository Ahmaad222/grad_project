# detection/threat_manager.py

from core.event_bus import event_queue, threat_queue
from detection.risk_engine import RiskEngine
import datetime


class ThreatManager:

    def __init__(self):
        self.engine = RiskEngine()
        self.history = {}          # عداد لكل BSSID لتأكيد التهديد
        self.last_status = {}      # لتجنب إعادة الطباعة للحالة نفسها
        self.confirmed_rogues = set()  # لتأكيد Rogue مرة واحدة فقط

    def print_event(self, event_summary):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        print("-" * 60)
        print(f"[{timestamp}] NEW ACCESS POINT DETECTED")
        print(f"SSID      : {event_summary['ssid']}")
        print(f"BSSID     : {event_summary['bssid']}")
        print(f"Channel   : {event_summary['channel']}")
        print(f"Signal    : {event_summary['signal']}")
        print(f"Encryption: {event_summary['encryption']}")
        print(f"Clients   : {event_summary['clients']}")
        print(f"Status    : {event_summary['classification']}")
        print(f"Score     : {event_summary['score']}")
        print(f"Reasons   : {', '.join(event_summary['reasons']) if event_summary['reasons'] else 'None'}")
        print("-" * 60)

    def start(self):
        while True:
            event = event_queue.get()
            # risk_engine الآن يرجع dict كامل
            event_summary = self.engine.analyze(event)

            bssid = event_summary["bssid"]
            status = event_summary["classification"]
            score = event_summary["score"]
            reasons = event_summary["reasons"]

            # عداد التكرار لتأكيد التهديد
            if bssid not in self.history:
                self.history[bssid] = 1
            else:
                self.history[bssid] += 1

            # اطبع الحدث إذا أول مرة أو الحالة تغيرت
            if bssid not in self.last_status or self.last_status[bssid] != status:
                self.print_event(event_summary)
                self.last_status[bssid] = status

            # 🚨 تأكيد Rogue بعد 3 مرات (مرة واحدة فقط)
            if status == "ROGUE" and self.history[bssid] >= 3 and bssid not in self.confirmed_rogues:
                self.confirmed_rogues.add(bssid)

                threat = {
                    "status": status,
                    "score": score,
                    "reasons": reasons,
                    "event": event_summary
                }

                print("\n🚨🚨🚨 ROGUE ACCESS POINT CONFIRMED 🚨🚨🚨")
                print(f"SSID      : {event_summary['ssid']}")
                print(f"BSSID     : {event_summary['bssid']}")
                print(f"Score     : {score}")
                print(f"Clients   : {event_summary['clients']}")
                print("Reasons   :")
                for r in reasons:
                    print(f"  - {r}")
                print("=" * 60)

                threat_queue.put(threat)
