import hashlib

class ForensicHasher:
    """Handles cryptographic hash calculation for evidence integrity."""
    
    def __init__(self, chunk_size: int = 4194304):
        self.chunk_size = chunk_size

    def calculate_sha256(self, file_path: str) -> str:
        """
        Calculates the SHA-256 hash of a file by reading it in chunks to optimize RAM.
        Returns the hexadecimal string or an error code in case of I/O failure.
        """
        try:
            sha256_hash = hashlib.sha256()
            
            with open(file_path, "rb") as f:
                # Iterate over the file stream via chunks to keep the memory footprint small
                for chunk in iter(lambda: f.read(self.chunk_size), b""):
                    sha256_hash.update(chunk)
                    
            return sha256_hash.hexdigest()
            
        except PermissionError:
            return "PERMISSION_ERROR"
        except Exception as e:
            return f"GENERIC_ERROR: {e}"