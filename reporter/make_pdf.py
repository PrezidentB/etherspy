from fpdf import FPDF
from datetime import datetime

class MakePDF:

    SAVE_PATH = "data/exports/"
    FONTS_PATH = "data/fonts/"
    IMAGES_PATH = "data/src/"

    def __init__(self, title):
        assert isinstance(title, str), "Le titre doit être une chaîne de caractères."
        assert len(title) > 0, "Le titre ne peut pas être vide."

        self.title = title
        self.pdf = FPDF(orientation='P', unit='mm', format='A4')
        self.pdf.set_margins(left=25, top=22, right=25)
        self.pdf.set_auto_page_break(auto=True, margin=25)
        self.pdf.add_font("Horizon", "", f"{self.FONTS_PATH}horizon.otf", uni=True)
        self.pdf.add_font("Outlined", "", f"{self.FONTS_PATH}outlined.otf", uni=True)
        self.pdf.add_font("SpacemonoReg", "", f"{self.FONTS_PATH}SpaceMono-Regular.ttf", uni=True)
        self.pdf.add_font("SpacemonoBld", "", f"{self.FONTS_PATH}SpaceMono-Bold.ttf", uni=True)
        self.pdf.set_page_background(background=f"{self.IMAGES_PATH}background.jpg")
        
        self.pdf.add_page()

        self.pdf.set_font("Horizon", size=20)
        self.pdf.set_y(self.pdf.h / 2 - 25)
        self.pdf.cell(w=self.pdf.w - 50, txt="Rapport d'analyse réseau", align="L")

        self.pdf.set_font("Horizon", size=12)
        self.pdf.set_y(self.pdf.h / 2 - 5)
        self.pdf.cell(w=self.pdf.w - 50, txt=f"Généré le {datetime.now().strftime('%d/%m/%Y')}", align="L")

        self.pdf.set_font("Outlined", size=20)
        self.pdf.set_y(self.pdf.h / 2 - 15)
        self.pdf.cell(w=self.pdf.w - 50, txt="Ether//Spy", align="L")
        
    def next(self):
        self.pdf.set_page_background(background=f"{self.IMAGES_PATH}pages.jpg")
        self.pdf.add_page()
        self.header()
        self.footer()

    def add_title(self, title):
        self.pdf.set_font("Horizon", size=20)
        self.pdf.set_y(25)
        self.pdf.set_x(25)
        self.pdf.multi_cell(w=0, txt=title, align="L")

    def add_paragraph(self, text):
        self.pdf.set_font("SpacemonoReg", size=12)
        self.pdf.set_y(self.pdf.get_y() + 10)
        self.pdf.set_x(25)
        self.pdf.multi_cell(w=0, txt=text, align="L", border=0)

    def add_graph_and_table(self, buffer, dict_data):
        self.pdf.set_y(self.pdf.get_y() + 10)
        self.pdf.set_x(25)
        self.pdf.image(buffer, x=(self.pdf.w - 120) / 2, w=120)

        # Tableau des données
        self.pdf.set_y(self.pdf.get_y() + 5)
        self.pdf.set_x(25)

        headers = ["Champ", "Valeur"]
        col_widths = ((self.pdf.w - 50)/2, (self.pdf.w - 50)/2)

        # En-tête du tableau
        self.pdf.set_fill_color(145, 172, 210)
        self.pdf.set_font("SpacemonoBld", size=12)
        for i in range(2):
            self.pdf.cell(col_widths[i], 10, headers[i], border=1, align="C", fill=True)
        self.pdf.ln()

        # Contenu du tableau
        for key, value in dict_data.items():
            self.pdf.set_font("SpacemonoReg", size=10)
            self.pdf.cell(col_widths[0], 7, str(key), border=1, align="C")
            self.pdf.cell(col_widths[1], 7, str(value), border=1, align="C")
            self.pdf.ln()

    def add_anomalies(self, anomalies):
        self.pdf.set_y(self.pdf.get_y() + 10)
        self.pdf.set_x(25)
        self.pdf.set_font("SpacemonoReg", size=12)

        for key, value in anomalies["Anomalies de protocole"].items():
            self.pdf.cell(w=0, txt=f"Protocole {key}: {value} anomalies remontées.", align="L")
            self.pdf.ln()

    
    def add_toc(self):
        """
        Ajoute une table des matières au PDF.
        """
        # flemme de le faire honnêtement
        # à faire plus tard
        pass
    
    def header(self):
        """
        Ajoute un en-tête au PDF.
        """
        self.pdf.set_font("SpacemonoReg", size=10)
        self.pdf.set_y(5)
        self.pdf.set_x(5)
        self.pdf.cell(w=0, txt="Ether//Spy", align="L")

        self.pdf.set_x(-40)
        self.pdf.cell(w=0, txt="Dorian BIOJOUT", align="L")

    def footer(self):
        # # Position cursor at 1.5 cm from bottom:
        # self.pdf.set_y(-15)
        # # Setting font: helvetica italic 8
        # self.pdf.set_font("SpacemonoReg", size=10)
        # # Printing page number:
        # self.pdf.cell(0, 10, f"Page {self.pdf.page_no()}/{{nb}}", align="C")
        # J'y arrive po
        pass

    def add_conclusion(self):
        """
        Ajoute une conclusion au PDF.
        """
        self.pdf.set_font("Horizon", size=20)
        self.pdf.set_y(self.pdf.get_y() + 10)
        self.pdf.set_x(25)
        self.pdf.cell(w=0, txt="Conclusion", align="L")

        self.pdf.set_y(self.pdf.get_y() + 10)
        self.pdf.set_x(25)
        self.pdf.set_font("SpacemonoReg", size=12)
        self.pdf.multi_cell(w=0, txt="Ce rapport présente une analyse détaillée des données réseau collectées, permettant d'identifier des anomalies présnetent dans une capture réseau. Pour une analyse plus poussée il est conseillé d'utiliser des outils comme WIreshark. ", align="L")
        
        self.pdf.set_y(self.pdf.get_y() + 10)
        self.pdf.set_x(25)
        self.pdf.set_font("SpacemonoReg", size=7)
        self.pdf.cell(w=0, txt="Merci d'avoir utilisé Ether//Spy.", align="L")

    def save(self):
        """
        Enregistre le PDF.
        """
        self.pdf.output(f"{self.SAVE_PATH}{self.title}.pdf")
        return f"PDF sauvegardé à {self.SAVE_PATH}{self.title}.pdf"