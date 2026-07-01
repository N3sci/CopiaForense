import os
import tkinter as tk
from tkinter import filedialog, messagebox

from forensic_hasher import ForensicHasher
from forensic_copier import ForensicCopier
from logger_pdf import ForensicReport


def prompt_directory_selection() -> tuple[str, str]:
    """Inizializza l'interfaccia grafica e acquisisce i percorsi operativi."""
    root = tk.Tk()
    root.withdraw()
    
    messagebox.showinfo(
        "Acquisizione Forense", 
        "Premi OK per selezionare:\n\n1. La cartella SORGENTE (Reperto)\n2. La cartella di DESTINAZIONE (Pendrive)"
    )

    sorgente = filedialog.askdirectory(title="1. Seleziona la cartella SORGENTE (Reperto)")
    destinazione = filedialog.askdirectory(title="2. Seleziona la cartella di DESTINAZIONE (Pendrive)")

    return sorgente, destinazione


def is_safe_path(source: str, dest: str) -> bool:
    """Valida che il path di destinazione non sia annidato all'interno della sorgente."""
    source_abs = os.path.abspath(source)
    dest_abs = os.path.abspath(dest)
    return os.path.commonpath([source_abs, dest_abs]) != source_abs


def process_directories(source_dir: str, dest_dir: str) -> list[dict]:
    """
    Orchestra l'esplorazione del file system, l'hashing e la copia logica.
    Restituisce la struttura dati completa contenente il registro delle operazioni.
    """
    hasher = ForensicHasher(chunk_size=65536)
    copier = ForensicCopier()
    registro = []

    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)

    for root, _, files in os.walk(source_dir):
        percorso_relativo = os.path.relpath(root, source_dir)
        cartella_dest_corrente = os.path.join(dest_dir, percorso_relativo)
        
        if not os.path.exists(cartella_dest_corrente):
            os.makedirs(cartella_dest_corrente)

        for nome_file in files:
            percorso_sorgente = os.path.join(root, nome_file)
            percorso_destinazione = os.path.join(cartella_dest_corrente, nome_file)
            percorso_visivo = os.path.normpath(os.path.join(percorso_relativo, nome_file))

            dati_file = {
                "percorso": percorso_visivo,
                "esito": "SALTATO",
                "hash_sha256": "N/D",
                "note_errore": ""
            }

            hash_originale = hasher.calculate_sha256(percorso_sorgente)
            
            if hash_originale.startswith("ERRORE"):
                dati_file["note_errore"] = f"Errore I/O in lettura sorgente ({hash_originale})"
                print(f"[⚠️ SALTATO] {percorso_visivo} (Accesso Negato)")
                registro.append(dati_file)
                continue 

            successo, msg_errore = copier.copy_file_with_metadata(percorso_sorgente, percorso_destinazione)

            if successo:
                hash_copia = hasher.calculate_sha256(percorso_destinazione)
                if hash_originale == hash_copia:
                    dati_file["esito"] = "SUCCESSO"
                    dati_file["hash_sha256"] = hash_originale
                    print(f"[✅ OK] {percorso_visivo}")
                else:
                    dati_file["esito"] = "FALLITO"
                    dati_file["note_errore"] = "Integrità compromessa: mismatch dell'hash post-copia"
                    print(f"[❌ ALTERATO] {percorso_visivo}")
            else:
                dati_file["note_errore"] = msg_errore
                print(f"[⚠️ ERRORE COPIA] {percorso_visivo} - {msg_errore}")
            
            registro.append(dati_file)

    return registro


def main() -> None:
    """Entry point dell'applicativo."""
    print("Inizializzazione ambiente forense...")
    cartella_sorgente, cartella_destinazione = prompt_directory_selection()

    if not cartella_sorgente or not cartella_destinazione:
        print("❌ Acquisizione annullata dall'operatore.")
        return

    if not is_safe_path(cartella_sorgente, cartella_destinazione):
        errore_msg = (
            "ERRORE FORENSE CRITICO:\n"
            "La cartella di destinazione risiede all'interno della sorgente.\n"
            "Rischio di ricorsione infinita e alterazione del reperto."
        )
        print(f"❌ {errore_msg}")
        
        root_alert = tk.Tk()
        root_alert.withdraw()
        messagebox.showerror("Violazione di Sicurezza", errore_msg)
        return

    print(f"📁 Target Acquisizione: {cartella_sorgente}")
    print(f"💾 Storage Destinazione: {cartella_destinazione}\n")
    print("Avvio procedura di estrazione logica...")
    
    registro_operazioni = process_directories(cartella_sorgente, cartella_destinazione)

    print(f"\nOperazioni concluse. File processati: {len(registro_operazioni)}")
    print("Generazione del verbale PDF in corso...")
    
    report_pdf = ForensicReport(operatore="Operatore PG - Nesci")
    percorso_report = os.path.join(cartella_destinazione, "Verbale_Acquisizione.pdf")
    report_pdf.genera_pdf(registro_operazioni, percorso_report)
    
    print(f"✅ Report consolidato con successo in: {percorso_report}")


if __name__ == "__main__":
    main()