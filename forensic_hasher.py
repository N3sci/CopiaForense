import hashlib

class ForensicHasher:
    """Gestisce il calcolo degli hash crittografici per l'integrità dei reperti."""
    
    def __init__(self, chunk_size: int = 4194304):
        self.chunk_size = chunk_size

    def calculate_sha256(self, file_path: str) -> str:
        """
        Calcola l'hash SHA-256 di un file leggendolo a blocchi per ottimizzare la RAM.
        Restituisce la stringa esadecimale o un codice di errore in caso di fallimento I/O.
        """
        try:
            sha256_hash = hashlib.sha256()
            
            with open(file_path, "rb") as f:
                # Itera sul file stream via chunk per contenere l'impronta in RAM
                for chunk in iter(lambda: f.read(self.chunk_size), b""):
                    sha256_hash.update(chunk)
                    
            return sha256_hash.hexdigest()
            
        except PermissionError:
            return "ERRORE_PERMESSI"
        except Exception as e:
            return f"ERRORE_GENERICO: {e}"