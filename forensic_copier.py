import shutil

class ForensicCopier:
    """Gestisce la clonazione fisica dei dati e la preservazione dei metadati."""
    
    def copy_file_with_metadata(self, source_path: str, dest_path: str) -> tuple[bool, str]:
        """
        Esegue la copia bit-a-bit e tenta di trasferire i metadati (MAC times).
        Restituisce una tupla contenente l'esito (bool) e un messaggio diagnostico.
        """
        try:
            shutil.copyfile(source_path, dest_path)
            
            try:
                shutil.copystat(source_path, dest_path)
                return True, ""
            except OSError:
                return True, "Copiato (Metadati originali non supportati dal File System di destinazione)"
                
        except PermissionError:
            return False, "Accesso negato in lettura (PermissionError)"
        except OSError:
            return False, "File bloccato o in uso dall'OS"
        except Exception as e:
            return False, f"Errore generico di copia: {e}"