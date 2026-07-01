import os
import json
import shutil
import platform
from datetime import datetime, timezone
import tkinter as tk
from tkinter import filedialog, messagebox

from forensic_hasher import ForensicHasher
from forensic_copier import ForensicCopier
from logger_pdf import ForensicReport

# --- UTILITIES E CONTROLLI PRE-VOLO ---

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

def check_disk_space(source: str, dest: str) -> bool:
    """Verifica che la destinazione abbia spazio sufficiente (+10% di buffer) per ospitare il reperto."""
    total_size = 0
    for dirpath, _, filenames in os.walk(source):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if not os.path.islink(fp):
                total_size += os.path.getsize(fp)
                
    required_space = total_size * 1.10 # 10% di margine per i log forensi
    free_space = shutil.disk_usage(dest).free
    return free_space >= required_space

def format_mac_time(timestamp: float) -> str:
    """Converte un timestamp Unix in formato UTC leggibile."""
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# --- CORE LOGIC ---

def process_directories(source_dir: str, dest_dir: str) -> list[dict]:
    """
    Orchestra l'estrazione metadati, l'esplorazione del file system, l'hashing e la copia logica.
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

            # Dizionario Dati Base
            dati_file = {
                "percorso": percorso_visivo,
                "esito": "SALTATO",
                "hash_sha256": "N/D",
                "note_errore": "",
                "dimensione_byte": 0,
                "data_modifica": "N/D",
                "data_accesso": "N/D",
                "data_creazione": "N/D"
            }

            # ESTRAZIONE METADATI MAC TIMES E DIMENSIONE
            try:
                stat_info = os.stat(percorso_sorgente)
                dati_file["dimensione_byte"] = stat_info.st_size
                dati_file["data_modifica"] = format_mac_time(stat_info.st_mtime)
                dati_file["data_accesso"] = format_mac_time(stat_info.st_atime)
                dati_file["data_creazione"] = format_mac_time(stat_info.st_ctime)
            except OSError as e:
                dati_file["note_errore"] = f"Impossibile estrarre metadati originali: {e}"

            # HASH PRE-COPIA
            hash_originale = hasher.calculate_sha256(percorso_sorgente)
            if hash_originale.startswith("ERRORE"):
                dati_file["note_errore"] += f" | Errore I/O in lettura sorgente ({hash_originale})"
                print(f"[⚠️ SALTATO] {percorso_visivo} (Accesso Negato)")
                registro.append(dati_file)
                continue 

            # COPIA FORENSE E VALIDAZIONE POST-COPIA
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


# --- GENERAZIONE REPORT E FIRME ---

def genera_report_strutturato(registro: list[dict], path_destinazione: str) -> str:
    """Serializza il registro in formato JSON per l'ingestione automatizzata (es. ElasticSearch/Splunk)."""
    json_path = os.path.join(path_destinazione, "Verbale_Strutturato.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(registro, f, indent=4, ensure_ascii=False)
    return json_path

def firma_catena_custodia(paths_verbali: list[str], path_destinazione: str):
    """Calcola l'hash dei verbali generati per garantirne l'immodificabilità."""
    hasher = ForensicHasher()
    firma_path = os.path.join(path_destinazione, "Certificato_Firma_Verbali.txt")
    
    with open(firma_path, 'w', encoding='utf-8') as f:
        f.write("=== CERTIFICATO DI IMMODIFICABILITA' DEI VERBALI ===\n")
        f.write(f"Data: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        for path in paths_verbali:
            hash_val = hasher.calculate_sha256(path)
            nome_file = os.path.basename(path)
            f.write(f"{nome_file}\nSHA-256: {hash_val}\n\n")


def main() -> None:
    """Entry point dell'applicativo."""
    print("Inizializzazione ambiente forense...")
    cartella_sorgente, cartella_destinazione = prompt_directory_selection()

    # 1. Controlli di Sicurezza
    if not cartella_sorgente or not cartella_destinazione:
        print("❌ Acquisizione annullata dall'operatore.")
        return

    if not is_safe_path(cartella_sorgente, cartella_destinazione):
        msg = "ERRORE CRITICO: Destinazione interna alla sorgente. Rischio loop infinito."
        messagebox.showerror("Violazione di Sicurezza", msg)
        return

    print("Verifica spazio su disco in corso...")
    if not check_disk_space(cartella_sorgente, cartella_destinazione):
        msg = "ERRORE CAPACITA': Spazio insufficiente sul disco di destinazione."
        messagebox.showerror("Spazio Insufficiente", msg)
        return

    # 2. Acquisizione
    print(f"📁 Target Acquisizione: {cartella_sorgente}")
    print(f"💾 Storage Destinazione: {cartella_destinazione}\n")
    print("Avvio procedura di estrazione logica...")
    
    registro_operazioni = process_directories(cartella_sorgente, cartella_destinazione)

    # 3. Reportistica
    print(f"\nOperazioni concluse. File processati: {len(registro_operazioni)}")
    print("Generazione catena di custodia in corso...")
    
    # PDF
    report_pdf = ForensicReport(operatore="Operatore PG")
    path_pdf = os.path.join(cartella_destinazione, "Verbale_Acquisizione.pdf")
    report_pdf.genera_pdf(registro_operazioni, path_pdf)
    
    # JSON Strutturato
    path_json = genera_report_strutturato(registro_operazioni, cartella_destinazione)
    
    # Firma Verbali
    firma_catena_custodia([path_pdf, path_json], cartella_destinazione)
    
    print(f"✅ Acquisizione completata e sigillata in: {cartella_destinazione}")


if __name__ == "__main__":
    main()