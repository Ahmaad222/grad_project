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

        packet = RadioTap() / \
                 Dot11(addr1=client,
                       addr2=bssid,
                       addr3=bssid) / \
                 Dot11Deauth(reason=7)

        sendp(packet,
              iface=self.iface,
              count=DEAUTH_COUNT,
              inter=DEAUTH_INTERVAL,
              verbose=False)