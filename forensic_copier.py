import shutil

class ForensicCopier:
    """Handles physical cloning of data and metadata preservation."""
    
    def copy_file_with_metadata(self, source_path: str, dest_path: str) -> tuple[bool, str]:
        """
        Executes a bit-by-bit copy and attempts to transfer metadata (MAC times).
        Returns a tuple containing the outcome (bool) and a diagnostic message.
        """
        try:
            shutil.copyfile(source_path, dest_path)
            
            try:
                shutil.copystat(source_path, dest_path)
                return True, ""
            except OSError:
                return True, "Copied (Original metadata not supported by destination File System)"
                
        except PermissionError:
            return False, "Read access denied (PermissionError)"
        except OSError:
            return False, "File locked or in use by OS"
        except Exception as e:
            return False, f"Generic copy error: {e}"