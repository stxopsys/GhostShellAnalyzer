# GhostShellAnalyzer

**APT-Level Shellcode Detector**  
Developed by `<starls/>`

---

## 📋 Description

**GhostShellAnalyzer** is an APT-level Windows tool for detecting in-memory shellcode injections and inline hooks. Its dark-mode GUI offers two scan modes:

- **Normal Scan**: Scans all processes looking for RWX regions, `.text` section modifications, and high-entropy blocks.  
- **Forensic Scan**: A stricter mode that only flags unsigned executable regions with extremely high entropy.

It also performs a **File Scan** of entropy on files (`.exe`, `.dll`, `.efi`, `.xml`, `.json`) in the current folder.


---

## ⚙️ Features

- **Memory Detection**  
  - RWX pages  
  - High-entropy regions (configurable threshold)  
- **Hook Detection**  
  - Compares in-memory `.text` section vs. on-disk image  
  - Byte-difference threshold alerts  
- **File Entropy Scan**  
  - Scans key file extensions for anomalous entropy  
- **Smart Whitelist**  
  - System processes _(svchost, explorer, RuntimeBroker…)_ are tagged but **still scanned** in Normal mode  
  - In Forensic mode, Microsoft-signed processes are skipped  
- **Dark-mode GUI** with RichEdit and buttons for:  
  - Normal Scan  
  - Forensic Scan  
  - Clear Log  
  - Infinite scroll and severity-color coding  
- **Timestamped Logs** `[HH:MM:SS]` with colors:  
  - 🟢 OK  
  - 🔵 WHITE (whitelisted)  
  - 🟡 HOOK  
  - 🔴 DETECT / UNSIGNED / FOR-DET  
  - ⚫ SCAN  

---

## 🛠️ Requirements

- Windows 10 or later (x64)  
- Visual Studio 2019/2022 (MSVC)  
- Windows SDK (Win32 APIs)  

---

## 🔧 Build Instructions

1. **Clone the repository**  
   ```bash
   git clone https://github.com/your-username/GhostShellAnalyzer.git
   cd GhostShellAnalyzer
