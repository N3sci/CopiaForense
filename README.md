# Strumento di Acquisizione Logica Forense

Questo progetto è un applicativo portable sviluppato in Python per l'acquisizione logica di dati e file a fini forensi. È progettato per garantire la catena di custodia, l'immodificabilità del dato (Art. 359 CPP) e la ripetibilità dell'operazione, risolvendo le problematiche comuni che si verificano durante le copie di massa su file system eterogenei.

## 🚀 Caratteristiche Principali

- **Integrità Crittografica:** Calcolo automatico dell'hash **SHA-256** pre e post-copia. La validazione 1:1 garantisce l'assoluta corrispondenza tra il reperto originale e la copia.
- **Estrazione MAC Times:** Preservazione e storicizzazione a verbale dei metadati temporali originali (Data Modifica, Accesso e Creazione) tramite `os.stat`, bypassando i limiti dei file system di destinazione (es. FAT32).
- **Sandboxing e Gestione Eccezioni:** Il motore di copia intercetta blocchi del Sistema Operativo (file in uso) e `PermissionError`, registrandoli a verbale senza interrompere il flusso operativo (No Crash).
- **Bypass MAX_PATH (Windows):** Implementazione dinamica del prefisso `\\?\` per aggirare il limite storico dei 260 caratteri dei percorsi Windows.
- **Sicurezza Anti-Inception:** Controllo algoritmico basato su `os.path.commonpath` per impedire la selezione di una destinazione annidata all'interno della sorgente (previene i loop di ricorsione).
- **Pre-flight Check:** Calcolo dello spazio richiesto (con buffer del 10%) prima di interagire con il supporto originale.
- **Reportistica Duale e Firma:** Generazione automatica di un verbale *Human-Readable* (PDF) e uno *Machine-Readable* (JSON). Il tool conclude l'operazione generando una firma SHA-256 dei verbali stessi per certificarne l'immodificabilità.

## 🛠️ Requisiti e Librerie

Il progetto utilizza principalmente moduli della Standard Library di Python (`os`, `shutil`, `hashlib`, `tkinter`).
L'unica dipendenza esterna richiesta per la generazione del verbale è:
- `fpdf2`

Per installare le dipendenze in ambiente di sviluppo:
```bash
pip install -r requirements.txt