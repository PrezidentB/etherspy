from sniffer.sniffers import LiveSniffer, PcapSniffer
from saver.savers import PcapSaver, TextSaver
from filter.filters import Filter
from reporter.graph import Graph
from reporter.make_pdf import MakePDF
from statistics.anomalies import Anomalies
from statistics.analyzer import Analyzer
from concurrent.futures import ThreadPoolExecutor

class MainController:
    """
    MainController est la classe principale qui gère l'analyse des paquets.

    Elle joue le role d'orchestrateur entre les différentes classes de sniffing, d'analyse et de statistiques.
    """

    def __init__(self, mode, pcap_path=None, live_iface=None, duration=None, output_file=None, protocol_filter="None", report=None):

        self.mode = mode
        self.pcap_path = pcap_path
        self.live_iface = live_iface
        self.duration = int(duration) if duration else None
        self.output_file = output_file if output_file else None
        self.protocol_filter = protocol_filter
        self.report = report

    def run(self):
        if self.mode == "live":
            sniffer = LiveSniffer(iface=self.live_iface, duration=self.duration)
            sniffer.start_with_progress()
            packets = sniffer.packets

            if self.protocol_filter != "None":
                filtering = Filter(packets)
                packets = filtering.apply_filter(self.protocol_filter)

            if self.output_file:
                if self.output_file.endswith(".pcap") or self.output_file.endswith(".pcapng"):
                    saver = PcapSaver(filename=self.output_file)

                elif self.output_file.endswith(".txt"):
                    saver = TextSaver(filename=self.output_file) 
                
                saver.save(packets)
            
        elif self.mode == "file":
            sniffer = PcapSniffer(self.pcap_path)
            sniffer.start_with_progress()
            packets = sniffer.packets

            if self.protocol_filter != "None":
                filtering = Filter(packets)
                packets = filtering.apply_filter(self.protocol_filter)

            if self.output_file != None:
                if self.output_file.endswith(".pcap") or self.output_file.endswith(".pcapng"):
                    saver = PcapSaver(filename=self.output_file)

                elif self.output_file.endswith(".txt"):
                    saver = TextSaver(filename=self.output_file) 
                
                saver.save(packets)

        if self.report != "None":
            analyzer = Analyzer(packets)
            anomalies = Anomalies(packets)

            # Utile si plus de 10 000 paquets, sinon pas de différence
            with ThreadPoolExecutor() as executor:
                future_top_protos = executor.submit(analyzer.top_protos)
                future_top_addr = executor.submit(analyzer.top_addr)
                future_traffic_over_time = executor.submit(analyzer.traffic_over_time, interval=analyzer.get_default_interval())
                future_anomalies = executor.submit(anomalies.run)

                top_protos = future_top_protos.result()
                top_addr = future_top_addr.result()
                traffic_over_time = future_traffic_over_time.result()
                anomalies_result = future_anomalies.result()

            
            graph = Graph(top_protos)
            graph2 = Graph(top_addr)
            graph3 = Graph(traffic_over_time)

            buffer1 = graph.bar_graph(title="Top 10 des protocoles", xlabel="Protocoles", ylabel="Nb de paquets")
            buffer2 = graph2.bar_graph(title="Top 10 des adresses", xlabel="Adresses", ylabel="Nb de paquets") 
            buffer3 = graph3.simple_plot(title="Traffic réseau au cours du temps", xlabel="Temps", ylabel="Nb de paquets")
                
            pdf = MakePDF(self.report)
            pdf.next()
            pdf.add_title("Top 10 des protocoles")
            pdf.add_paragraph("Voici les 10 protocoles les plus utilisés dans la capture réseau.")
            pdf.add_graph_and_table(buffer1, top_protos)

            pdf.next()
            pdf.add_title("Top 10 des adresses")
            pdf.add_paragraph("Voici les 10 adresses les plus utilisées dans la capture réseau.")
            pdf.add_graph_and_table(buffer2, top_addr)
            
            pdf.next()
            pdf.add_title("Traffic réseau")
            pdf.add_paragraph("Voici le traffic réseau au cours du temps.")
            pdf.add_graph_and_table(buffer3, traffic_over_time)

            pdf.next()
            pdf.add_title("Anomalies détectées")
            pdf.add_paragraph("Voici les anomalies détectées dans la capture réseau.")
            pdf.add_anomalies(anomalies_result)
            pdf.add_conclusion()
            
            return pdf.save()

    