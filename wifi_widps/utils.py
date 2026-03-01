# utils.py

from scapy.layers.dot11 import Dot11Elt

def get_ssid(packet):
    elt = packet.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 0:
            try:
                return elt.info.decode(errors="ignore")
            except:
                return "Hidden"
        elt = elt.payload.getlayer(Dot11Elt)
    return "Hidden"


def extract_channel(packet):
    elt = packet.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 3:
            if elt.info:
                return elt.info[0]
        elt = elt.payload.getlayer(Dot11Elt)
    return None