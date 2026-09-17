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
    """Initializes the graphical interface and acquires operational paths."""
    root = tk.Tk()
    root.withdraw()
    messagebox.showinfo(
        "Forensic Acquisition", 
        "Press OK to select:\n\n1. The SOURCE folder (Evidence)\n2. The DESTINATION folder (USB/Drive)"
    )
    source = filedialog.askdirectory(title="1. Select the SOURCE folder (Evidence)")
    destination = filedialog.askdirectory(title="2. Select the DESTINATION folder (USB/Drive)")
    
    # Destroys the Tkinter root to prevent UI thread hanging on macOS (WindowServer beach balling)
    root.destroy()
    
    return source, destination

def is_safe_path(source: str, dest: str) -> bool:
    """Validates that the destination path is not nested within the source."""
    source_abs = os.path.abspath(source)
    dest_abs = os.path.abspath(dest)
    return os.path.commonpath([source_abs, dest_abs]) != source_abs

def check_disk_space(source: str, dest: str) -> bool:
    """Verifies that the destination has sufficient space (+10% buffer) to host the evidence."""
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
    """Converts a Unix timestamp to a readable UTC format."""
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# --- CORE LOGIC ---
CHUNK_SIZE = 4194304  # 4MB

def process_directories(source_dir: str, dest_dir: str) -> list[dict]:
    """
    Orchestrates metadata extraction, file system traversal, hashing, and logical copying.
    Returns the complete data structure containing the operations registry.
    """
    hasher = ForensicHasher(chunk_size=CHUNK_SIZE)
    copier = ForensicCopier()
    registry = []
    dir_metadata_to_copy = []

    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)

    for root, _, files in os.walk(source_dir):
        relative_path = os.path.relpath(root, source_dir)
        current_dest_folder = os.path.join(dest_dir, relative_path)
        
        if not os.path.exists(current_dest_folder):
            os.makedirs(current_dest_folder)
            
        # Store directory paths to restore original MAC times post-copy
        dir_metadata_to_copy.append((root, current_dest_folder))

        for file_name in files:
            source_path = os.path.join(root, file_name)
            destination_path = os.path.join(current_dest_folder, file_name)
            visual_path = os.path.normpath(os.path.join(relative_path, file_name))

            # Base Data Dictionary
            file_data = {
                "path": visual_path,
                "status": "SKIPPED",
                "hash_sha256": "N/A",
                "error_notes": "",
                "size_bytes": 0,
                "modification_date": "N/A",
                "access_date": "N/A",
                "change_or_creation_date": "N/A"
            }

            # METADATA MAC TIMES AND SIZE EXTRACTION
            try:
                stat_info = os.stat(source_path)
                file_data["size_bytes"] = stat_info.st_size
                file_data["modification_date"] = format_mac_time(stat_info.st_mtime)
                file_data["access_date"] = format_mac_time(stat_info.st_atime)
                file_data["change_or_creation_date"] = format_mac_time(stat_info.st_ctime)
            except OSError as e:
                file_data["error_notes"] = f"Unable to extract original metadata: {e}"

            # PRE-COPY HASH
            original_hash = hasher.calculate_sha256(source_path)
            if original_hash.startswith("ERROR") or original_hash.startswith("PERMISSION"):
                file_data["error_notes"] += f" | I/O Error reading source ({original_hash})"
                print(f"[⚠️ SKIPPED] {visual_path} (Access Denied)")
                registry.append(file_data)
                continue 

            # FORENSIC COPY AND POST-COPY VALIDATION
            success, msg_error = copier.copy_file_with_metadata(source_path, destination_path)

            if success:
                copy_hash = hasher.calculate_sha256(destination_path)
                if original_hash == copy_hash:
                    file_data["status"] = "SUCCESS"
                    file_data["hash_sha256"] = original_hash
                    print(f"[✅ OK] {visual_path}")
                else:
                    file_data["status"] = "FAILED"
                    file_data["error_notes"] = "Integrity compromised: post-copy hash mismatch"
                    print(f"[❌ ALTERED] {visual_path}")
            else:
                file_data["error_notes"] = msg_error
                print(f"[⚠️ COPY ERROR] {visual_path} - {msg_error}")
            
            registry.append(file_data)

    # Restore directory metadata at the end to prevent I/O alterations
    for src_dir, dst_dir in dir_metadata_to_copy:
        try:
            shutil.copystat(src_dir, dst_dir)
        except OSError:
            pass

    return registry


# --- REPORT GENERATION AND SIGNATURES ---

def generate_structured_report(registry: list[dict], destination_path: str, source_name: str = "") -> str:
    """Serializes the registry in JSON format for automated ingestion (e.g., ElasticSearch/Splunk)."""
    file_name = f"Structured_Report_{source_name}.json" if source_name else "Structured_Report.json"
    json_path = os.path.join(destination_path, file_name)
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(registry, f, indent=4, ensure_ascii=False)
    return json_path

def generate_chain_of_custody_certificate(report_paths: list[str], destination_path: str, source_name: str = ""):
    """Calculates the hash of the generated reports to ensure their immutability."""
    hasher = ForensicHasher()
    file_name = f"Chain_of_Custody_Certificate_{source_name}.txt" if source_name else "Chain_of_Custody_Certificate.txt"
    signature_path = os.path.join(destination_path, file_name)
    
    with open(signature_path, 'w', encoding='utf-8') as f:
        f.write("=== CERTIFICATE OF IMMUTABILITY OF REPORTS ===\n")
        f.write(f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        for path in report_paths:
            hash_val = hasher.calculate_sha256(path)
            report_file_name = os.path.basename(path)
            f.write(f"{report_file_name}\nSHA-256: {hash_val}\n\n")


def main() -> None:
    """Application entry point."""
    print("Initializing forensic environment...")
    source_folder, destination_folder = prompt_directory_selection()

    # 1. Security Checks
    if not source_folder or not destination_folder:
        print("❌ Acquisition canceled by the operator.")
        return

    if not is_safe_path(source_folder, destination_folder):
        msg = "CRITICAL ERROR: Destination is inside the source. Risk of infinite loop."
        messagebox.showerror("Security Violation", msg)
        return

    print("Verifying disk space in progress...")
    if not check_disk_space(source_folder, destination_folder):
        msg = "CAPACITY ERROR: Insufficient space on the destination disk."
        messagebox.showerror("Insufficient Space", msg)
        return

    # 2. Acquisition
    print(f"📁 Acquisition Target: {source_folder}")
    print(f"💾 Destination Storage: {destination_folder}\n")
    print("Starting logical extraction procedure...")
    
    # Initialize the destination root dir maintaining the name of the source volume/folder
    source_name = os.path.basename(os.path.normpath(source_folder))
    if not source_name:
        source_name = "Evidence_Acquisition"
        
    acquisition_folder = os.path.join(destination_folder, source_name)
    
    operations_registry = process_directories(source_folder, acquisition_folder)

    # 3. Reporting
    print(f"\nOperations concluded. Processed files: {len(operations_registry)}")
    print("Generating chain of custody in progress...")
    
    # PDF
    report_pdf = ForensicReport(operator="PG Operator")
    pdf_path = os.path.join(destination_folder, f"Acquisition_Report_{source_name}.pdf")
    report_pdf.generate_pdf_summary(operations_registry, pdf_path)
    
    # Structured JSON
    json_path = generate_structured_report(operations_registry, destination_folder, source_name)
    
    # Reports Hash Certificate
    generate_chain_of_custody_certificate([pdf_path, json_path], destination_folder, source_name)
    
    print(f"✅ Acquisition completed and sealed in: {destination_folder}")


if __name__ == "__main__":
    main()