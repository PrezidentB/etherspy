from collections import defaultdict, Counter
from scapy.all import IP, PacketList
import datetime

class Analyzer:
    PROTOCOL_TO_OSI = {
        "Ethernet": 2,
        "Dot3": 2,
        "ARP": 2,
        "IP": 3,
        "IPv6": 3,
        "ICMP": 3,
        "TCP": 4,
        "UDP": 4,
        "DNS": 7,
        "HTTP": 7,
        "TLS": 6,
    }

    def __init__(self, packets):
        assert isinstance(packets, PacketList)

        self.packets = packets

    def proto_count(self):
        protocol_counter = defaultdict(int)

        for pkt in self.packets:
            current_layer = pkt
            while current_layer:
                layer_name = current_layer.__class__.__name__
                protocol_counter[layer_name] += 1
                current_layer = current_layer.payload

                # fin si plus de payload
                if current_layer is None or current_layer == b'':
                    break

        return dict(sorted(protocol_counter.items(), key=lambda x: x[1], reverse=True))

    def top_addr(self):
        addr_counter = Counter()

        for pkt in self.packets:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                addr_counter[src] += 1
                addr_counter[dst] += 1

        return dict(addr_counter.most_common(10))

    def top_protos(self):
        return self.proto_count()

    def traffic_over_time(self, interval=10):
        """
        Retourne le trafic par intervalle de temps.
        
        :interval: Intervalle de temps en secondes.

        :return: Un dictionnaire avec les timestamps comme clés et le nombre de paquets comme valeurs.
        """

        if not self.packets:
            return {}

        start_time = float(self.packets[0].time)
        time_buckets = defaultdict(int)

        for pkt in self.packets:
            pkt_time = float(pkt.time)
            bucket_index = int((pkt_time - start_time) // interval)
            bucket_time = datetime.datetime.fromtimestamp(start_time + bucket_index * interval)
            time_buckets[bucket_time] += 1

        # Conversion en dictionnaire ordonné (optionnel si ordre important)
        return dict(sorted(time_buckets.items()))
    
    def get_default_interval(self):
        """
        Retourne l'intervalle par défaut pour la capture de paquets.
        """
        start = float(self.packets[0].time)
        end = float(self.packets[-1].time)
        duration = end - start

        if duration < 60:
            return 1
        elif duration < 300:
            return 10
        elif duration < 1800:
            return 30
        elif duration < 3600:
            return 60
        else:
            return 300
