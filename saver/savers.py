from scapy.all import PacketList, wrpcap

class Saver:
    
    """
    Classe abstraite pour sauvegarder des paquets, fonctionne sous linux, pas testé sous windows.
    """

    def __init__(self, path, filename):
        self.path = path
        self.filename = filename
        self.fullpath = f"{path}{filename}"

    def save(self, pkts):
        assert isinstance(pkts, PacketList), "pkts doit être une liste de paquets"

    def get_fullpath(self):
        return self.fullpath
    

class PcapSaver(Saver):

    EXTENSION = ".pcapng"
    FILEPATH = "data/samples/"

    def __init__(self, filename):
        super().__init__(path=self.FILEPATH, filename=filename)

    def save(self, pkts):
        super().save(pkts)
        try:
            wrpcap(filename=self.get_fullpath(), pkt=pkts)
            return (0, f"Saved {len(pkts)} packets in {self.get_fullpath()}")
        except Exception as e:
            return (1, f"Error while saving packets: {e}")
        

class TextSaver(Saver):

    EXTENSION = ".txt"
    FILEPATH = "data/samples/"

    def __init__(self, filename):
        super().__init__(path=self.FILEPATH, filename=filename)

    def save(self, pkts):
        super().save(pkts)
        try:
            with open(self.get_fullpath(), "w") as f:
                for pkt in pkts:
                    f.write(str(pkt) + "\n")
            return (0, f"Saved {len(pkts)} packets in {self.get_fullpath()}")
        except Exception as e:
            return (1, f"Error while saving packets: {e}")