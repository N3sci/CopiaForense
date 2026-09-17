from fpdf import FPDF
from datetime import datetime, timezone

class ForensicReport:
    """Generates the PDF Executive Summary of the acquisition."""
    
    def __init__(self, operator: str = "Operating Agent"):
        self.operator = operator
        self.acquisition_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def generate_pdf_summary(self, data_registry: list[dict], save_path: str) -> None:
        """Creates a single-page PDF with global statistics, omitting the file list."""
        pdf = FPDF(orientation="P", unit="mm", format="A4")
        pdf.add_page()
        
        # HEADER
        pdf.set_font("helvetica", style="B", size=16)
        pdf.cell(0, 10, "FORENSIC LOGICAL ACQUISITION REPORT", align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5) 
        
        # OPERATION METADATA
        pdf.set_font("helvetica", style="B", size=12)
        pdf.cell(0, 8, "OPERATION DETAILS", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", size=11)
        pdf.cell(0, 8, f"Acquisition Date: {self.acquisition_date}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, f"Operator: {self.operator}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

        # STATISTICS
        total = len(data_registry)
        successes = sum(1 for f in data_registry if f.get("status") == "SUCCESS")
        anomalies = total - successes
        
        pdf.set_font("helvetica", style="B", size=12)
        pdf.cell(0, 8, "ACQUISITION STATISTICS", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", size=11)
        pdf.cell(0, 8, f"Total Files Detected : {total}", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 128, 0)
        pdf.cell(0, 8, f"Successful Copies    : {successes}", new_x="LMARGIN", new_y="NEXT")
        
        if anomalies > 0:
            pdf.set_text_color(200, 0, 0)
        else:
            pdf.set_text_color(0, 0, 0)
            
        pdf.cell(0, 8, f"Anomalies / Skipped  : {anomalies}", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
        pdf.ln(10)

        # ATTACHMENTS DECLARATION
        pdf.set_font("helvetica", style="I", size=10)
        note = (
            "NOTE: To ensure the readability of the report and manage massive amounts of data, "
            "the detailed list of acquired files, including original paths, "
            "sizes, timestamps (MAC times), and SHA-256 cryptographic signatures pre/post copy, "
            "is exclusively deferred to the structured attachments (JSON/Text Files) "
            "included in the destination media."
        )
        pdf.multi_cell(0, 6, note)
            
        pdf.output(save_path)