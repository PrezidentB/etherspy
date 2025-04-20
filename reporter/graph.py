from matplotlib import pyplot as plt
from io import BytesIO
import numpy as np

class Graph:

    SAVE_PATH = "data/src/"

    def __init__(self, data):
        assert isinstance(data, dict), "Data must be a dictionary."
        self.data = data
        self.x = list(data.keys())
        self.y = list(data.values())

    def bar_graph(self, title="Bar Graph", xlabel="X-axis", ylabel="Y-axis"):
        """
        Crée un histogramme avec les données d'entrée.

        Prends seulement les 10 premiers éléments du dictionnaire.
        """

        buffer = BytesIO()

        fig, ax = plt.subplots()
        ax.bar(self.x[:10], self.y[:10], color='blue')
        ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
        ax.grid()
        plt.xticks(rotation=45)
        plt.tight_layout(pad=2.0)
        fig.savefig(buffer, format="png", dpi=300)
        buffer.seek(0)
        plt.close(fig)

        return buffer

    def simple_plot(self, title="Simple Plot", xlabel="X-axis", ylabel="Y-axis"):
        """
        Crée un graphique simple avec les données d'entrée.
        """

        buffer = BytesIO()

        fig, ax = plt.subplots()
        ax.plot(self.x, self.y, color='blue')
        ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
        ax.grid()
        plt.tight_layout(pad=2.0)
        plt.xticks(rotation=30)
        fig.savefig(buffer, format="png", dpi=300)
        buffer.seek(0)
        plt.close(fig)

        return buffer