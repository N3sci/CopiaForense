from fpdf import FPDF
from datetime import datetime, timezone

class ForensicReport:
    """Genera il verbale PDF riassuntivo (Executive Summary) dell'acquisizione."""
    
    def __init__(self, operatore: str = "Agente Operante"):
        self.operatore = operatore
        self.data_acquisizione = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def genera_pdf_riassuntivo(self, registro_dati: list[dict], percorso_salvataggio: str) -> None:
        """Crea un PDF di singola pagina con le statistiche globali, omettendo la lista file."""
        pdf = FPDF(orientation="P", unit="mm", format="A4")
        pdf.add_page()
        
        # INTESTAZIONE
        pdf.set_font("helvetica", style="B", size=16)
        pdf.cell(0, 10, "VERBALE DI ACQUISIZIONE LOGICA FORENSE", align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5) 
        
        # METADATI OPERAZIONE
        pdf.set_font("helvetica", style="B", size=12)
        pdf.cell(0, 8, "DETTAGLI OPERAZIONE", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", size=11)
        pdf.cell(0, 8, f"Data Acquisizione: {self.data_acquisizione}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, f"Operatore: {self.operatore}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

        # STATISTICHE
        totale = len(registro_dati)
        successi = sum(1 for f in registro_dati if f.get("esito") == "SUCCESSO")
        anomalie = totale - successi
        
        pdf.set_font("helvetica", style="B", size=12)
        pdf.cell(0, 8, "STATISTICHE DI ACQUISIZIONE", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", size=11)
        pdf.cell(0, 8, f"Totale File Rilevati : {totale}", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 128, 0)
        pdf.cell(0, 8, f"Copie con Successo   : {successi}", new_x="LMARGIN", new_y="NEXT")
        
        if anomalie > 0:
            pdf.set_text_color(200, 0, 0)
        else:
            pdf.set_text_color(0, 0, 0)
            
        pdf.cell(0, 8, f"Anomalie / Saltati   : {anomalie}", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.ln(10)

        # DICHIARAZIONE ALLEGATI
        pdf.set_font("helvetica", style="I", size=10)
        nota = (
            "NOTA: Per garantire la leggibilita' del verbale e gestire moli di dati massive, "
            "l'elenco dettagliato dei file acquisiti, inclusivi di percorsi originari, "
            "dimensioni, timestamp (MAC times) e firme crittografiche SHA-256 pre/post copia, "
            "e' demandato esclusivamente agli allegati strutturati (File JSON/Testuali) "
            "inclusi nel supporto di destinazione."
        )
        pdf.multi_cell(0, 6, nota)
            
        pdf.output(percorso_salvataggio)