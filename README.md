# PE Anomaly Scanner 🔍

A Python-based static analysis tool that scans Windows PE 
executables for malware indicators with a suspicion score.

## What it checks
- SHA256 hash → VirusTotal lookup link
- Compilation timestamp → detects wiped/faked timestamps
- Section entropy → flags packed/encrypted sections (>7.2)
- Import analysis → detects suspicious APIs used by malware
- Overlay data → hidden payloads after last section

## Suspicious imports detected
- VirtualAllocEx + WriteProcessMemory + CreateRemoteThread = Process Injection
- CryptEncrypt / CryptDecrypt = Ransomware
- InternetOpen / WinInet = C2 communication
- RegSetValueEx = Registry persistence

## Usage
```bash
pip install pefile
python pe_anomaly.py
```

 ## Skills Demonstrated
- PE format internals
- Static malware analysis
- Python binary analysis
- Suspicion scoring system

#MalwareAnalysis #CyberSecurity #Python #PEFormat
