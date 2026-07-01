from fpdf import FPDF
from datetime import datetime, timezone

class ForensicReport:
    """Genera il verbale PDF ufficiale dell'acquisizione logica."""
    
    def __init__(self, operatore: str = "Agente Operante"):
        self.operatore = operatore
        self.data_acquisizione = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def _sana_testo(self, testo: str) -> str:
        """
        Esegue il fallback dei caratteri non supportati dal font Latin-1 (es. emoji, CJK),
        prevenendo l'eccezione UnicodeEncodeError durante il rendering vettoriale.
        """
        if not testo:
            return ""
        return str(testo).encode('latin-1', errors='replace').decode('latin-1')

    def genera_pdf(self, registro_dati: list[dict], percorso_salvataggio: str) -> None:
        """Compila e serializza il documento PDF su disco."""
        pdf = FPDF(orientation="P", unit="mm", format="A4")
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        pdf.set_font("helvetica", style="B", size=16)
        pdf.cell(0, 10, "VERBALE DI ACQUISIZIONE LOGICA FORENSE", align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5) 
        
        pdf.set_font("helvetica", size=11)
        pdf.cell(0, 8, f"Data Acquisizione: {self.data_acquisizione}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, f"Operatore: {self.operatore}", new_x="LMARGIN", new_y="NEXT")
        
        totale = len(registro_dati)
        successi = sum(1 for f in registro_dati if f.get("esito") == "SUCCESSO")
        anomalie = totale - successi
        
        pdf.cell(0, 8, f"Totale File Processati: {totale} ({successi} Successi, {anomalie} Anomalie)", new_x="LMARGIN", new_y="NEXT")
        pdf.line(10, pdf.get_y() + 2, 200, pdf.get_y() + 2)
        pdf.ln(10)
        
        for file_data in registro_dati:
            esito = file_data.get("esito", "SALTATO")
            percorso_sicuro = self._sana_testo(file_data.get('percorso', ''))
            errore_sicuro = self._sana_testo(file_data.get('note_errore', ''))
            
            if esito == "SUCCESSO":
                pdf.set_text_color(0, 128, 0)
            elif esito == "SALTATO":
                pdf.set_text_color(204, 102, 0)
            else:
                pdf.set_text_color(200, 0, 0)
                
            pdf.set_font("helvetica", style="B", size=10)
            pdf.multi_cell(0, 6, f"[{esito}] {percorso_sicuro}", new_x="LMARGIN", new_y="NEXT")
            
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("courier", size=9) 
            
            if esito == "SUCCESSO":
                pdf.multi_cell(0, 5, f"    SHA-256: {file_data.get('hash_sha256', 'N/D')}", new_x="LMARGIN", new_y="NEXT")
            else:
                pdf.multi_cell(0, 5, f"    Errore : {errore_sicuro}", new_x="LMARGIN", new_y="NEXT")
            
            pdf.ln(3)
            
        pdf.output(percorso_salvataggio)