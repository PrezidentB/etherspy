from scapy.all import sniff, wrpcap, rdpcap
from scapy.plist import PacketList
from tqdm import tqdm
import threading, time, os

class SnifferException(Exception):
    pass

class Sniffer:
    def __init__(self, source):
        assert source is not None, "Le source ne peut pas être None."

    def sniff(self):
        pass


class PcapSniffer(Sniffer):
    def __init__(self, source):
        super().__init__(source)
        assert os.path.isfile(source), f"Le fichier {source} n'existe pas."
        assert source.endswith(".pcap") or source.endswith(".pcapng"), SnifferException(f"Le fichier {source} n'est pas un fichier pcap valide.")

        self.__source = source

    def _capture(self):
        """
        Capture des paquets à partir d'un fichier pcap.
        """
        self.packets = rdpcap(self.__source)

    def start_with_progress(self):
        capture_thread = threading.Thread(target=self._capture)
        capture_thread.start()

        # Spinner pour indiquer le chargement
        spinner = "|/-\\"
        idx = 0
        while capture_thread.is_alive():
            print(f"\r⏳ Chargement en cours {spinner[idx % len(spinner)]}", end="")
            idx += 1
            time.sleep(0.1)
        print("\r", end="")  # Clear the spinner line

        capture_thread.join()
        print(f"✅ Chargement terminé : {len(self.packets)} paquets chargés.")
    

class LiveSniffer(Sniffer):
    def __init__(self, iface="eth0", duration=10):
        super().__init__(iface)
        assert isinstance(iface, str)
        self.__iface = iface
        self.__duration = duration
        self.packets = PacketList()
    
    def _capture(self):
        """
        Capture des paquets en temps réel sur l'interface spécifiée.
        """
        self.packets = sniff(iface=self.__iface, timeout=self.__duration)

    def start_with_progress(self):
        print(f"🎯 Capture sur {self.__iface} pendant {self.__duration} secondes...")
        capture_thread = threading.Thread(target=self._capture)
        capture_thread.start()

        # Barre de chargement
        for _ in tqdm(range(self.__duration), desc="⏳ Capture en cours", unit="s"):
            time.sleep(1)

        capture_thread.join()
        print(f"✅ Capture terminée : {len(self.packets)} paquets capturés.")