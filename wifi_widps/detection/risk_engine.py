# detection/risk_engine.py

from config import TRUSTED_APS


class RiskEngine:

    def analyze(self, event):
        """
        يحلل event ويحسب درجة الخطورة.
        - event: dict مع keys:
            bssid, ssid, channel, signal, encryption, clients
        """

        score = 0
        reasons = []

        ssid = event.get("ssid")
        bssid = event.get("bssid")
        channel = event.get("channel")
        signal = event.get("signal")
        encryption = event.get("encryption")
        clients = event.get("clients", 0)

        # 🔹 Open network مع عملاء متصلين
        if encryption == "OPEN" and clients > 0:
            score += 5
            reasons.append("Open network with connected clients")

        # 🔹 الشبكة معروفة / trusted
        if ssid in TRUSTED_APS:
            trusted = TRUSTED_APS[ssid]

            # Evil Twin (SSID مطابق لكن BSSID مختلف)
            if bssid.lower() != trusted["bssid"].lower():
                score += 6
                reasons.append("Evil Twin suspected")

            # Channel mismatch
            if channel != trusted["channel"]:
                score += 2
                reasons.append("Channel mismatch")

        # 🔹 SSID غير معروف
        else:
            score += 3
            reasons.append("SSID not trusted")

        # 🔹 إشارة قوية بشكل غير طبيعي
        if signal is not None and signal > -30:
            score += 2
            reasons.append("Unusually strong signal")

        classification = self.classify(score)

        # إضافة معلومات clients للتقرير النهائي
        event_summary = {
            "classification": classification,
            "score": score,
            "reasons": reasons,
            "bssid": bssid,
            "ssid": ssid,
            "channel": channel,
            "signal": signal,
            "encryption": encryption,
            "clients": clients
        }

        return event_summary

    def classify(self, score):
        if score >= 6:
            return "ROGUE"
        elif score >= 3:
            return "SUSPICIOUS"
        return "LEGIT"
