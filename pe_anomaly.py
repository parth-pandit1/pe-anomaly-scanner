import math
import pefile
import datetime
def entropy(data):  
    if not data: return 0
    freq = [data.count(bytes([b]))/len(data) for b in set(data)]
    return -sum(p * math.log2(p) for p in freq if p > 0)
def analyze_pe(filepath):
    print(f"\n{'='*55}")
    print(f"FILE: {filepath}")
    print(f"{'='*55}")
    
    score = 0  # suspicion score — 0 se 10 tak
    reasons = []  # kyun suspicious hai
    import hashlib
    with open(filepath, 'rb') as f:
        data = f.read()
    sha256 = hashlib.sha256(data).hexdigest()
    print(f"\nSHA256: {sha256}")
    print(f"VT: https://virustotal.com/gui/file/{sha256}")
    try:
        pe = pefile.PE(filepath)
    except pefile.PEFormatError:
        print("PE parse failed — packed/corrupted!")
        score += 3
        reasons.append("PE parse failed — heavily packed")
        return score, reasons
    try:
        pe = pefile.PE(filepath)
    except pefile.PEFormatError:
        print("PE parse failed — packed/corrupted!")
        score += 3
        reasons.append("PE parse failed — heavily packed")
        return score, reasons
    ts = pe.FILE_HEADER.TimeDateStamp
    dt = datetime.datetime.fromtimestamp(ts)
    year = dt.year
    print(f"\nCompiled: {dt}")
    
    if year < 2000 or year > 2026:
        print("  ⚠️ SUSPICIOUS timestamp!")
        score += 2
        reasons.append(f"Manipulated timestamp: {dt}")
    else:
        print("  ✅ Normal timestamp")
        print(f"\n--- IMPORTS ---")
    suspicious_imports = [
        'VirtualAllocEx', 'WriteProcessMemory', 
        'CreateRemoteThread',  # process injection!
        'CryptEncrypt', 'CryptDecrypt',  # ransomware!
        'WinInet', 'InternetOpen',  # C2 connection!
        'RegSetValueEx',  # registry persistence!
    ]
    
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode()
            print(f"  {dll}")
            for imp in entry.imports:
                if imp.name:
                    fn = imp.name.decode()
                    if fn in suspicious_imports:
                        print(f"    ⚠️ SUSPICIOUS: {fn}")
                        score += 1
                        reasons.append(f"Suspicious import: {fn}")
    except:
        pass
    # Overlay check
    overlay = pe.get_overlay()
    if overlay:
        print(f"\n⚠️ OVERLAY DATA: {len(overlay)} bytes!")
        score += 2
        reasons.append(f"Overlay data: {len(overlay)} bytes")
    else:
        print(f"\n✅ No overlay data")
        # Final score
    print(f"\n{'='*55}")
    print(f"SUSPICION SCORE: {score}/10")
    
    if score <= 3:
        print("VERDICT: ✅ Probably clean")
    elif score <= 6:
        print("VERDICT: ⚠️ Suspicious — investigate!")
    else:
        print("VERDICT: 🚨 HIGHLY SUSPICIOUS — likely malware!")
    
    if reasons:
        print("\nReasons:")
        for r in reasons:
            print(f"  → {r}")
    
    return score, reasons
# Notepad pe test karo
analyze_pe('C:\\Windows\\System32\\notepad.exe')
