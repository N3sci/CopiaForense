import os
import json
import argparse
import shutil
import binascii

def revert_denied_permissions(original_path, entry):
    if os.path.exists(original_path):
        os.chmod(original_path, 0o644)
        return True
    return False

def revert_symlink_loop(original_path, entry):
    symlink_path = entry.get("new_path")
    if symlink_path and os.path.islink(symlink_path):
        os.unlink(symlink_path)
        return True
    return False

def revert_deep_path(original_path, entry):
    new_path = entry.get("new_path")
    if new_path and os.path.exists(new_path):
        shutil.move(new_path, original_path)
        deep_dir = os.path.dirname(new_path)
        try:
            os.removedirs(deep_dir)
        except OSError:
            pass
        return True
    return False

def revert_rename(original_path, entry):
    new_path = entry.get("new_path")
    if new_path and os.path.exists(new_path):
        os.rename(new_path, original_path)
        return True
    return False

def revert_time_stomping(original_path, entry):
    metadata = entry.get("metadata", {})
    if "original_atime" in metadata and "original_mtime" in metadata:
        if os.path.exists(original_path):
            os.utime(original_path, (metadata["original_atime"], metadata["original_mtime"]))
            return True
    return False

def revert_corrupted_magic(original_path, entry):
    metadata = entry.get("metadata", {})
    hex_original = metadata.get("original_header_hex")
    if hex_original and os.path.exists(original_path):
        original_bytes = binascii.unhexlify(hex_original)
        with open(original_path, 'r+b') as f:
            f.seek(0)
            f.write(original_bytes)
        return True
    # If the file was too small, it was not corrupted and metadata is empty
    return True

def main():
    parser = argparse.ArgumentParser(description="Script to revert the injection of anomalies.")
    parser.add_argument("--input", default="ground_truth.json", help="Path to the ground truth file")
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"Error: File '{args.input}' not found.")
        return
        
    with open(args.input, "r", encoding="utf-8") as f:
        ground_truth = json.load(f)

    success_count = 0
    error_count = 0
    
    for original_path, entry in ground_truth.items():
        anomaly = entry.get("anomaly")
        if "error" in entry: continue
            
        success = False
        try:
            if anomaly == "denied_permissions":
                success = revert_denied_permissions(original_path, entry)
            elif anomaly == "symlink_loop":
                success = revert_symlink_loop(original_path, entry)
            elif anomaly == "deep_path":
                success = revert_deep_path(original_path, entry)
            elif anomaly in ("mismatched_extensions", "anomalous_names"):
                success = revert_rename(original_path, entry)
            elif anomaly == "time_stomping":
                success = revert_time_stomping(original_path, entry)
            elif anomaly == "corrupted_magic":
                success = revert_corrupted_magic(original_path, entry)
                
            if success:
                success_count += 1
            else:
                error_count += 1
        except Exception as e:
            error_count += 1
            
    print(f"Files successfully reverted: {success_count}")
    if error_count > 0:
        print(f"Files with errors: {error_count}")

if __name__ == "__main__":
    main()
