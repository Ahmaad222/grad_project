# main.py

import threading
from monitoring.sniffer import start_monitoring
from detection.threat_manager import ThreatManager
from prevention.response_engine import ResponseEngine


def main():

    print("🔥 WIDPS System Started...\n")

    tm = ThreatManager()
    re = ResponseEngine()

    t1 = threading.Thread(target=start_monitoring)
    t2 = threading.Thread(target=tm.start)
    t3 = threading.Thread(target=re.start)

    t1.start()
    t2.start()
    t3.start()

    t1.join()
    t2.join()
    t3.join()


if __name__ == "__main__":
    main()