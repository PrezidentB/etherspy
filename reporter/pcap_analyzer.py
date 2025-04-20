from ..statistics.analyzer import Analyzer

class PcapAnalyzer(Analyzer):

    def __init__(self):
        super().__init__()

    def dns_analyze(self, pkts, save=False, path=""):
        """
        Analyze DNS packets
        """
        super().analyze(pkts)

        self.count = 0
        self.qnames = []
        self.path = path

        for pkt in pkts:
            if pkt.haslayer('DNS'):
                qname = pkt['DNS'].qd.qname.decode()
                if len(qname) > 30:
                    self.count += 1
                    self.qnames.append(qname)
        if self.count == 0:
            return (0, "No DNS packet with a qname longer than 30 characters")

        if save:
            with open(f"{self.path}long_qnames.txt", "w") as f:
                for qname in self.qnames:
                    f.write(qname + "\n")
            return (0, f"Found {self.count} DNS packets with a qname longer than 30 characters, writing in {self.path}long_qnames.txt")
        else:
            return (0, f"Found {self.count} DNS packets with a qname longer than 30 characters")

    def http_analyzer(self, pkts, save=False, path=""):
        """
        Analyze HTTP packets
        """
        super().analyze(pkts)

        self.count = 0
        self.hosts = []
        self.path = path

        pass