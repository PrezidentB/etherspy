import questionary
import sys

RETURN_DICT = {
    "mode": None,
    "interface": None,
    "duration": None,
    "output_file": None,
    "protocol_filter": None,
    "pcap_file": None,
    "report": None
}

def __init__():
    pass

def launch():
    try:
        mode = questionary.select(
            "Mode de capture :",
            choices=["Live", "Fichier"]
        ).ask()

        if mode == "Live":
            return handle_live_mode()

        elif mode == "Fichier":
            return handle_file_mode()
        else:
            questionary.print("⚠️  Mode non reconnu.", style="bold italic fg:darkred")
            sys.exit(1)

    except KeyboardInterrupt:
        questionary.print("⚠️  Capture annulée par l'utilisateur.", style="bold italic fg:darkred")
        sys.exit(0)

def handle_live_mode():
    questionary.print("⚠️  Assurez-vous d'avoir les droits d'administrateur pour capturer des paquets.", style="bold italic fg:darkred")

    interface = questionary.text("Interface réseau :").ask()
    duration = questionary.text("Durée de la capture (en secondes) :").ask()
    protocol_filter = questionary.select(
        "Filtre à appliquer :",
        choices=["IP", "TCP", "UDP", "DNS", "ARP", "Ethernet", "None"]
    ).ask()
    output_file = questionary.text("Nom du fichier de sortie (.pcap, .pcapng ou .txt) :").ask()

    pdf_report = questionary.confirm("Générer un rapport PDF ?").ask()
    if pdf_report:
        report_name = questionary.text("Nom du rapport PDF :").ask()
    else:
        report_name = None

    questionary.print(f"Interface: {interface}, Durée: {duration}s, Fichier de sortie: {output_file}, Filtre: {protocol_filter}", style="bold italic fg:green")

    RETURN_DICT.update({
        "mode": "live",
        "interface": interface,
        "duration": duration,
        "output_file": output_file,
        "protocol_filter": protocol_filter,
        "report": report_name
    })
    return RETURN_DICT

def handle_file_mode():
    pcap_file = questionary.path("Chemin du fichier PCAP :").ask()

    pdf_report = questionary.confirm("Générer un rapport PDF ?").ask()
    if pdf_report:
        report_name = questionary.text("Nom du rapport PDF :").ask()
    else:
        report_name = None

    protocol_filter = questionary.select(
        "Filtre à appliquer :",
        choices=["IP", "TCP", "UDP", "DNS", "ARP", "Ethernet", "None"]
    ).ask()

    ask_output = questionary.confirm("Voulez-vous spécifier un fichier de sortie ?").ask()
    if ask_output:
        output_file = questionary.text("Nom du fichier de sortie (.pcap, .pcapng ou .txt) :").ask()
    else:
        output_file = None

    questionary.print(f"Fichier PCAP: {pcap_file}, Fichier de sortie: {output_file}, Filtre: {protocol_filter}", style="bold italic fg:green")

    RETURN_DICT.update({
        "mode": "file",
        "pcap_file": pcap_file,
        "output_file": output_file,
        "protocol_filter": protocol_filter,
        "report": report_name
    })
    return RETURN_DICT