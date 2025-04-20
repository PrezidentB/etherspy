import argparse, os, sys
from core.controller import MainController
from core.interface import launch

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Analyseur de paquets Ethernet (capture live ou lecture de fichier)"
    )

    subparsers = parser.add_subparsers(dest="mode", required=False, help="Mode de fonctionnement")

    # Mode Live
    live_parser = subparsers.add_parser("live", help="Capture réseau en temps réel et génération d'un rapport PDF post capture.")
    live_parser.add_argument(
        "-i", "--interface",
        default="eth0",
        help="Interface réseau à utiliser (défaut: eth0)"
    )
    live_parser.add_argument(
        "-d", "--duration",
        type=int,
        required=True,
        help="Durée de la capture en secondes"
    )
    live_parser.add_argument(
        "-o", "--output",
        required=True,
        help="Fichier de sortie (.pcap, .pcapng ou .txt)"
    )
    live_parser.add_argument(
        "-p", "--protocol",
        choices=["IP", "TCP", "UDP", "DNS", "ARP","Ethernet", "None"],
        default="None",
        help="Filtre protocolaire à appliquer"
    )
    live_parser.add_argument(
        "-r", "--report",
        action="store_true",
        default="rapport.pdf",
        help="Nom du rapport PDF à générer (défaut: rapport.pdf)"
    )

    # Mode File
    file_parser = subparsers.add_parser("file", help="Analyse d'un fichier PCAP existant et génération d'un rapport PDF.")
    file_parser.add_argument(
        "-f", "--file",
        required=True,
        help="Fichier PCAP ou PCAPNG à analyser"
    )
    file_parser.add_argument(
        "-o", "--output",
        required=True,
        help="Fichier de sortie (.pcap, .pcapng ou .txt)"
    )
    file_parser.add_argument(
        "-p", "--protocol",
        choices=["IP", "TCP", "UDP", "DNS", "ARP","Ethernet", "None"],
        default="All",
        help="Filtre protocolaire à appliquer"
    )
    file_parser.add_argument(
        "-r", "--report",
        action="store_true",
        default="rapport.pdf",
        help="Nom du rapport PDF à générer (défaut: rapport.pdf)"
    )

    # Mode interactif
    interactive_parser = parser.add_argument_group("Mode interactif")
    interactive_parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Lancer l'interface interactive"
    )

    return parser.parse_args()

def main():
    args = parse_arguments()

    if args.mode == "live":
        controller = MainController(
            live_iface=args.interface,
            duration=args.duration,
            output_file=args.output,
            protocol_filter=args.protocol,
            mode="live",
            report=args.report
        )

    elif args.mode == "file":
        controller = MainController(
            pcap_path=args.file,
            output_file=args.output,
            protocol_filter=args.protocol,
            mode="file",
            report=args.report
        )

    elif args.interactive:
        inputs = launch()
        controller = MainController(
            mode=inputs["mode"],
            pcap_path=inputs["pcap_file"],
            live_iface=inputs["interface"],
            duration=inputs["duration"],
            output_file=inputs["output_file"],
            protocol_filter=inputs["protocol_filter"],
            report=inputs["report"]
        )
    
    print(f"{controller.run()}")


if __name__ == "__main__":
    main()
