from scapy.all import PacketList
from scapy.all import Raw, Ether, IP, TCP, UDP, DNS, ARP
from scapy.layers.http import HTTPRequest
from scapy.layers import dns

class FilterError(Exception):
    pass

class Filter:
    def __init__(self, packets):
        assert isinstance(packets, PacketList)

        self.packets = packets
        self.protocol_map = {
            "IP": IP,
            "TCP": TCP,
            "UDP": UDP,
            "DNS": DNS,
            "ARP": ARP,
            "Ethernet": Ether,
        }

    def apply_filter(self, protocol):
        """
        Applique un filtre par nom de protocole, retourne un PacketList
        """
        layer = self.protocol_map.get(protocol)
        if not layer:
            raise FilterError(f"Protocole inconnu : {protocol}")

        filtered = [pkt for pkt in self.packets if pkt.haslayer(layer)]
        return PacketList(filtered, name=f"Filtré par {protocol}")


# ["IP", "TCP", "UDP", "DNS", "ARP", "Ethernet", "None"]