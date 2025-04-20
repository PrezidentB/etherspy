from scapy.all import *
from scapy.layers.dns import DNSQR
from scapy.layers.inet import ICMP

class Anomalies:
    ANOMALIES = {
        "Anomalies de protocole": {
            "ICMP": 0,
            "HTTP": 0,
            "DNS": 0,
        },
    }

    def __init__(self, packets):
        assert isinstance(packets, PacketList), "Les paquets doivent être une liste de paquets"
        self.packets = packets

    def dns_anomalies(self, packets):
        """
        Analyser les anomalies DNS dans les paquets.
        """
        for pkt in packets:
            if DNSQR in pkt:
                # Vérifier si le nom de domaine est trop long
                if len(pkt[DNSQR].qname) > 35:
                    self.ANOMALIES["Anomalies de protocole"]["DNS"] += 1

                # Vérifier si le nom de domaine contient des caractères spéciaux
                if any(char in pkt[DNSQR].qname.decode() for char in "!@#$%^&*()"):
                    self.ANOMALIES["Anomalies de protocole"]["DNS"] += 1
    
    def icmp_anomalies(self, packets):
        """
        Analyser les anomalies ICMP dans les paquets.
        """
        for pkt in packets:
            if ICMP in pkt:
                # Vérifier si le type ICMP est inconnu
                if pkt[ICMP].type not in [0, 3, 8, 11]:
                    self.ANOMALIES["Anomalies de protocole"]["ICMP"] += 1

                # Vérifier si le code ICMP est inconnu
                if pkt[ICMP].code not in [0, 1, 2]:
                    self.ANOMALIES["Anomalies de protocole"]["ICMP"] += 1

                # Vérifier si le message ICMP est trop long
                if len(pkt[ICMP].load) > 128:
                    self.ANOMALIES["Anomalies de protocole"]["ICMP"] += 1
                
                # Vérifier si le message ICMP contient des caractères spéciaux
                if any(char in pkt[ICMP].load.decode() for char in "!@#$%^&*()"):
                    self.ANOMALIES["Anomalies de protocole"]["ICMP"] += 1

    def http_anomalies(self, packets):
        pass

    def run(self):
        """
        Exécute l'analyse des anomalies sur les paquets.
        """
        self.dns_anomalies(self.packets)
        self.icmp_anomalies(self.packets)
        self.http_anomalies(self.packets)
        
        # Autres analyses d'anomalies peuvent être ajoutées ici
        return self.ANOMALIES
