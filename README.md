# Forensic Logical Acquisition Tool

This project is a portable application developed in Python for the logical acquisition of data and files for forensic purposes. It is designed to ensure the chain of custody, data immutability, and the repeatability of the operation, solving common issues that occur during mass copying across heterogeneous file systems.

## 🚀 Key Features

- **Cryptographic Integrity:** Automatic pre- and post-copy **SHA-256** hash calculation. The 1:1 validation ensures absolute correspondence between the original evidence and the copy.
- **MAC Times Extraction:** Preservation and reporting of the original temporal metadata (Modification, Access, and Creation Dates) via `os.stat`, bypassing the limitations of destination file systems (e.g., FAT32).
- **Sandboxing & Exception Handling:** The copy engine intercepts Operating System locks (files in use) and `PermissionError`s, recording them in the report without interrupting the operational flow (No Crash).
- **MAX_PATH Bypass (Windows):** Dynamic implementation of the `\\?\` prefix to bypass the historical 260-character path limit on Windows.
- **Anti-Inception Security:** Algorithmic check based on `os.path.commonpath` to prevent selecting a destination nested within the source (prevents recursion loops).
- **Pre-flight Check:** Calculation of required disk space (with a 10% buffer) before interacting with the original media.
- **Dual Reporting and Signature:** Automatic generation of a *Human-Readable* report (PDF) and a *Machine-Readable* one (JSON). The tool concludes the operation by generating a SHA-256 signature of the reports themselves to certify their immutability.

## 📦 Standalone Executables
The binary files attached to the GitHub Releases (automatically generated via GitHub Actions) do not require Python or other dependencies to be installed. Download the appropriate version for your operating system and CPU architecture:
- **Windows (Intel/AMD/ARM):** `CopiaForense-windows-x64.zip`
- **macOS (Intel):** `CopiaForense-macos-intel.zip`
- **macOS (Apple Silicon):** `CopiaForense-macos-silicon.zip`
- **Linux (Intel/AMD):** `CopiaForense-linux-x64.zip`
- **Linux (ARM64):** `CopiaForense-linux-arm64.zip`

## ⚠️ Running the Executables (macOS & Windows)

Because this tool is an independent open-source project and not digitally signed by a paid commercial certificate, your Operating System might initially block its execution. This is normal and expected behavior.

**For macOS Users (Gatekeeper):**
If you see an "Apple could not verify..." warning:
1. Go to **System Settings** -> **Privacy & Security**.
2. Scroll down to the security section and click **Open Anyway** next to the blocked app notification.
3. Alternatively, in Finder, **Right-Click** the executable and select **Open**.

**For Windows Users (SmartScreen):**
If you see a "Windows protected your PC" blue screen warning:
1. Click on **More info**.
2. Click the **Run anyway** button that appears at the bottom.

## 🛠️ Development Requirements

The project mainly uses modules from the Python Standard Library (`os`, `shutil`, `hashlib`, `tkinter`).
The only external dependency required for generating the PDF report is:
- `fpdf2`

To install the dependencies in a development environment:
```bash
pip install -r requirements.txt
