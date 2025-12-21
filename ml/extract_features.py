

# """
# Minimal, ML-clean static feature extraction for MSI files.
# Keeps only features validated by EDA + adds PE-structure features from extracted payloads.

# - MSI static features via msitools (msiinfo)
# - PE structure features via already-extracted files in Binary/<class>/<msi_name>/

# This remains 100% static (no execution).
# """

# import os
# import csv
# import math
# import subprocess
# import argparse
# import re
# from typing import Dict, List, Tuple, Optional

# # =========================
# # Basic utilities
# # =========================

# def shannon_entropy(data: bytes) -> float:
#     if not data:
#         return 0.0
#     freq = [0] * 256
#     for b in data:
#         freq[b] += 1
#     n = len(data)
#     ent = 0.0
#     for c in freq:
#         if c:
#             p = c / n
#             ent -= p * math.log2(p)
#     return ent

# def safe_log1p(x: float) -> float:
#     return math.log1p(max(0.0, x))

# def read_head(path: str, n: int = 4096) -> Tuple[float, int]:
#     size = os.path.getsize(path)
#     with open(path, "rb") as f:
#         head = f.read(n)
#     return shannon_entropy(head), size

# # =========================
# # msitools helpers
# # =========================

# def run_msiinfo_export(msi_path: str, table: str) -> Optional[str]:
#     try:
#         p = subprocess.run(
#             ["msiinfo", "export", msi_path, table],
#             capture_output=True,
#             text=True,
#             timeout=20
#         )
#     except Exception:
#         return None

#     if p.returncode != 0 or not p.stdout:
#         return None
#     return p.stdout

# def parse_idt(text: str) -> List[List[str]]:
#     lines = [l for l in (text or "").splitlines() if l.strip()]
#     if len(lines) < 4:
#         return []
#     rows = []
#     for l in lines[3:]:
#         parts = l.split("\t")
#         if parts:
#             rows.append(parts)
#     return rows

# # =========================
# # MSI feature extraction (ancien)
# # =========================

# EXEC_RE = re.compile(r"\.(exe|dll|bat|cmd|ps1|vbs|js)$", re.I)

# SUSPICIOUS_KW = [
#     "powershell", "cmd.exe", "rundll32", "regsvr32",
#     "mshta", "wscript", "cscript", "http://", "https://",
#     "base64", "invoke", "download"
# ]

# def kw_hits(s: str) -> int:
#     s = (s or "").lower()
#     return sum(k in s for k in SUSPICIOUS_KW)

# def extract_msi_features(msi_path: str) -> Dict[str, float]:
#     feats: Dict[str, float] = {}

#     # --- Size & entropy
#     head_ent, size = read_head(msi_path)
#     feats["log_size"] = safe_log1p(size)
#     feats["head_entropy"] = head_ent

#     # --- Binary table presence
#     feats["has_binary"] = 1.0 if run_msiinfo_export(msi_path, "Binary") else 0.0

#     # --- InstallExecuteSequence
#     ies_rows = parse_idt(run_msiinfo_export(msi_path, "InstallExecuteSequence") or "")
#     feats["ies_action_count"] = float(len(ies_rows))

#     exe_actions = 0
#     for r in ies_rows:
#         if r and EXEC_RE.search(r[0]):
#             exe_actions += 1
#     feats["ies_executable_action_count"] = float(exe_actions)

#     # --- CustomAction
#     ca_rows = parse_idt(run_msiinfo_export(msi_path, "CustomAction") or "")
#     feats["ca_count"] = float(len(ca_rows))

#     ca_exe = 0
#     ca_dll = 0
#     ca_deferred = 0
#     ca_commit = 0
#     ca_susp = 0

#     for r in ca_rows:
#         if len(r) < 2:
#             continue
#         action = r[0]
#         try:
#             t = int(r[1])
#         except ValueError:
#             t = 0

#         src = r[2] if len(r) > 2 else ""
#         tgt = r[3] if len(r) > 3 else ""
#         blob = " ".join([action, src, tgt])

#         base = t & 0x3F
#         if base == 2 or EXEC_RE.search(src) or EXEC_RE.search(tgt):
#             ca_exe += 1
#         if base == 1 or src.lower().endswith(".dll") or tgt.lower().endswith(".dll"):
#             ca_dll += 1
#         if t & 0x400:
#             ca_deferred += 1
#         if t & 0x2000:
#             ca_commit += 1

#         ca_susp += kw_hits(blob)

#     feats["ca_exe_count"] = float(ca_exe)
#     feats["ca_dll_count"] = float(ca_dll)
#     feats["ca_deferred_count"] = float(ca_deferred)
#     feats["ca_commit_count"] = float(ca_commit)
#     feats["ca_suspicious_kw_hits"] = float(ca_susp)

#     # --- LaunchCondition
#     lc_rows = parse_idt(run_msiinfo_export(msi_path, "LaunchCondition") or "")
#     feats["lc_count"] = float(len(lc_rows))

#     return feats

# # =========================
# # NEW: PE structure features from extracted payloads
# # =========================

# PE_EXTS = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr"}
# EXE_EXTS = {".exe", ".scr", ".cpl"}   # exécutables usuels
# DLL_EXTS = {".dll", ".ocx"}           # bibliothèques usuelles

# def count_pe_structure(extracted_root: str) -> Dict[str, float]:
#     """
#     extracted_root = Binary/<benign|malicious>/<msi_name>/
#     Returns minimal structure features:
#       - nb_pe_files
#       - nb_exe
#       - nb_dll
#       - exe_to_dll_ratio
#     """
#     nb_pe = 0
#     nb_exe = 0
#     nb_dll = 0

#     if not extracted_root or not os.path.isdir(extracted_root):
#         # Pas extrait / dossier manquant
#         return {
#             "nb_pe_files": 0.0,
#             "nb_exe": 0.0,
#             "nb_dll": 0.0,
#             "exe_to_dll_ratio": 0.0,
#         }

#     for dirpath, _, filenames in os.walk(extracted_root):
#         for fn in filenames:
#             ext = os.path.splitext(fn)[1].lower()
#             if ext in PE_EXTS:
#                 nb_pe += 1
#                 if ext in EXE_EXTS:
#                     nb_exe += 1
#                 if ext in DLL_EXTS:
#                     nb_dll += 1

#     ratio = (nb_exe / nb_dll) if nb_dll > 0 else float(nb_exe)

#     return {
#         "nb_pe_files": float(nb_pe),
#         "nb_exe": float(nb_exe),
#         "nb_dll": float(nb_dll),
#     }

# # =========================
# # Dataset builder
# # =========================

# # ⚠️ Tu m’as dit : “enlève les inutiles”
# # Ici je garde ton set MSI actuel (car tu l’avais EDA-validé),
# # et on AJOUTE seulement les 4 nouvelles structure features.
# FEATURES = [
#     # MSI features (ancien)
#     "log_size",
#     "head_entropy",
#     "has_binary",
#     "ies_action_count",
#     "ies_executable_action_count",
#     "ca_count",
#     "ca_exe_count",
#     "ca_dll_count",
#     "ca_deferred_count",
#     "ca_commit_count",
#     "ca_suspicious_kw_hits",
#     "lc_count",

#     # NEW: PE structure features
#     "nb_pe_files",
#     "nb_exe",
#     "nb_dll",
# ]

# def collect(dataset_root: str) -> List[Tuple[str, int]]:
#     out = []
#     for label, sub in [(0, "benign"), (1, "malicious")]:
#         d = os.path.join(dataset_root, sub)
#         for f in sorted(os.listdir(d)):
#             if f.lower().endswith(".msi"):
#                 out.append((os.path.join(d, f), label))
#     return out

# def extracted_folder_for(msi_path: str, label: int, bin_dir: str) -> str:
#     """
#     Maps dataset/<class>/<name>.msi -> Binary/<class>/<name>/
#     """
#     base = os.path.splitext(os.path.basename(msi_path))[0]
#     sub = "benign" if label == 0 else "malicious"
#     return os.path.join(bin_dir, sub, base)


# def main():
#     ap = argparse.ArgumentParser()
#     ap.add_argument("--dataset", default="dataset", help="dataset root containing benign/ and malicious/")
#     ap.add_argument("--bin", default="Binary", help="Binary extraction root containing benign/ and malicious/")
#     ap.add_argument("--out", default="ml/features.csv", help="output CSV path")
#     args = ap.parse_args()

#     # Resolve paths relative to where script is launched
#     # We assume run from project root or anywhere; normalize to absolute.
#     dataset_root = os.path.abspath(args.dataset)
#     bin_root = os.path.abspath(args.bin)

#     items = collect(dataset_root)
#     os.makedirs(os.path.dirname(args.out), exist_ok=True)

#     with open(args.out, "w", newline="", encoding="utf-8") as f:
#         writer = csv.DictWriter(f, fieldnames=["file", "label"] + FEATURES)
#         writer.writeheader()

#         for i, (msi_path, label) in enumerate(items, 1):
#             msi_name = os.path.basename(msi_path)
#             print(f"[{i}/{len(items)}] Extracting label={label} file={msi_name}")

#             # MSI-level features
#             feats = extract_msi_features(msi_path)

#             # PE structure features (from extracted folder)
#             extracted_root = extracted_folder_for(msi_path, label, bin_root)

#             pe_struct = count_pe_structure(extracted_root)

#             # merge
#             feats.update(pe_struct)

#             row = {"file": msi_name, "label": label}
#             for k in FEATURES:
#                 row[k] = feats.get(k, 0.0)
#             writer.writerow(row)

#     print(f"✅ CSV written to {args.out}")

# if __name__ == "__main__":
#     main()

import os
import csv
import math
import subprocess
import argparse
import re
from typing import Dict, List, Tuple, Optional

# =========================
# Basic utilities
# =========================

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent

def safe_log1p(x: float) -> float:
    return math.log1p(max(0.0, x))

def read_head(path: str, n: int = 4096) -> Tuple[float, int]:
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(n)
    return shannon_entropy(head), size

# =========================
# msitools helpers
# =========================

def run_msiinfo_export(msi_path: str, table: str) -> Optional[str]:
    try:
        p = subprocess.run(
            ["msiinfo", "export", msi_path, table],
            capture_output=True,
            text=True,
            timeout=20
        )
    except Exception:
        return None

    if p.returncode != 0 or not p.stdout:
        return None
    return p.stdout

def parse_idt(text: str) -> List[List[str]]:
    lines = [l for l in (text or "").splitlines() if l.strip()]
    if len(lines) < 4:
        return []
    rows = []
    for l in lines[3:]:
        parts = l.split("\t")
        if parts:
            rows.append(parts)
    return rows

# =========================
# MSI feature extraction (ancien)
# =========================

EXEC_RE = re.compile(r"\.(exe|dll|bat|cmd|ps1|vbs|js)$", re.I)

SUSPICIOUS_KW = [
    "powershell", "cmd.exe", "rundll32", "regsvr32",
    "mshta", "wscript", "cscript", "http://", "https://",
    "base64", "invoke", "download"
]

def kw_hits(s: str) -> int:
    s = (s or "").lower()
    return sum(k in s for k in SUSPICIOUS_KW)

def extract_msi_features(msi_path: str) -> Dict[str, float]:
    feats: Dict[str, float] = {}

    # --- Size & entropy
    head_ent, size = read_head(msi_path)
    feats["log_size"] = safe_log1p(size)
    feats["head_entropy"] = head_ent

    # --- Binary table presence
    feats["has_binary"] = 1.0 if run_msiinfo_export(msi_path, "Binary") else 0.0

    # --- InstallExecuteSequence
    ies_rows = parse_idt(run_msiinfo_export(msi_path, "InstallExecuteSequence") or "")
    feats["ies_action_count"] = float(len(ies_rows))

    exe_actions = 0
    for r in ies_rows:
        if r and EXEC_RE.search(r[0]):
            exe_actions += 1
    feats["ies_executable_action_count"] = float(exe_actions)

    # --- CustomAction
    ca_rows = parse_idt(run_msiinfo_export(msi_path, "CustomAction") or "")
    feats["ca_count"] = float(len(ca_rows))

    ca_exe = 0
    ca_dll = 0
    ca_deferred = 0
    ca_commit = 0
    ca_susp = 0

    for r in ca_rows:
        if len(r) < 2:
            continue
        action = r[0]
        try:
            t = int(r[1])
        except ValueError:
            t = 0

        src = r[2] if len(r) > 2 else ""
        tgt = r[3] if len(r) > 3 else ""
        blob = " ".join([action, src, tgt])

        base = t & 0x3F
        if base == 2 or EXEC_RE.search(src) or EXEC_RE.search(tgt):
            ca_exe += 1
        if base == 1 or src.lower().endswith(".dll") or tgt.lower().endswith(".dll"):
            ca_dll += 1
        if t & 0x400:
            ca_deferred += 1
        if t & 0x2000:
            ca_commit += 1

        ca_susp += kw_hits(blob)

    feats["ca_exe_count"] = float(ca_exe)
    feats["ca_dll_count"] = float(ca_dll)
    feats["ca_deferred_count"] = float(ca_deferred)
    feats["ca_commit_count"] = float(ca_commit)
    feats["ca_suspicious_kw_hits"] = float(ca_susp)

    # --- LaunchCondition
    lc_rows = parse_idt(run_msiinfo_export(msi_path, "LaunchCondition") or "")
    feats["lc_count"] = float(len(lc_rows))

    return feats

# =========================
# NEW: PE structure features from extracted payloads
# =========================

PE_EXTS = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr"}
EXE_EXTS = {".exe", ".scr", ".cpl"}   # exécutables usuels
DLL_EXTS = {".dll", ".ocx"}           # bibliothèques usuelles

def count_pe_structure(extracted_root: str) -> Dict[str, float]:
    """
    extracted_root = Binary/<benign|malicious>/<msi_id>/
    Returns minimal structure features:
      - nb_pe_files
      - nb_exe
      - nb_dll
    """
    nb_pe = 0
    nb_exe = 0
    nb_dll = 0

    if not extracted_root or not os.path.isdir(extracted_root):
        # Pas extrait / dossier manquant
        return {
            "nb_pe_files": 0.0,
            "nb_exe": 0.0,
            "nb_dll": 0.0,
        }

    for dirpath, _, filenames in os.walk(extracted_root):
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in PE_EXTS:
                nb_pe += 1
                if ext in EXE_EXTS:
                    nb_exe += 1
                if ext in DLL_EXTS:
                    nb_dll += 1

    return {
        "nb_pe_files": float(nb_pe),
        "nb_exe": float(nb_exe),
        "nb_dll": float(nb_dll),
    }

# =========================
# Dataset builder
# =========================

FEATURES = [
    # MSI features (ancien)
    "log_size",
    "head_entropy",
    "has_binary",
    "ies_action_count",
    "ies_executable_action_count",
    "ca_count",
    "ca_exe_count",
    "ca_dll_count",
    "ca_deferred_count",
    "ca_commit_count",
    "ca_suspicious_kw_hits",
    "lc_count",

    # NEW: PE structure features
    "nb_pe_files",
    "nb_exe",
    "nb_dll",
]

def collect(dataset_root: str) -> List[Tuple[str, int]]:
    out = []
    for label, sub in [(0, "benign"), (1, "malicious")]:
        d = os.path.join(dataset_root, sub)
        for f in sorted(os.listdir(d)):
            if f.lower().endswith(".msi"):
                out.append((os.path.join(d, f), label))
    return out

def extracted_folder_for(msi_id: str, label: int, bin_dir: str) -> str:
    """
    Maps (msi_id, label) -> Binary/<class>/<msi_id>/
    """
    sub = "benign" if label == 0 else "malicious"
    return os.path.join(bin_dir, sub, msi_id)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="dataset", help="dataset root containing benign/ and malicious/")
    ap.add_argument("--bin", default="Binary", help="Binary extraction root containing benign/ and malicious/")
    ap.add_argument("--out", default="ml/features.csv", help="output CSV path")
    args = ap.parse_args()

    dataset_root = os.path.abspath(args.dataset)
    bin_root = os.path.abspath(args.bin)

    items = collect(dataset_root)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        # ✅ ajout msi_id dans le CSV
        writer = csv.DictWriter(f, fieldnames=["msi_id", "file", "label"] + FEATURES)
        writer.writeheader()

        for i, (msi_path, label) in enumerate(items, 1):
            msi_name = os.path.basename(msi_path)
            msi_id = os.path.splitext(msi_name)[0]

            print(f"[{i}/{len(items)}] Extracting label={label} msi_id={msi_id}")

            # MSI-level features
            feats = extract_msi_features(msi_path)

            # PE structure features (from extracted folder)
            extracted_root = extracted_folder_for(msi_id, label, bin_root)
            pe_struct = count_pe_structure(extracted_root)

            feats.update(pe_struct)

            row = {"msi_id": msi_id, "file": msi_name, "label": label}
            for k in FEATURES:
                row[k] = feats.get(k, 0.0)
            writer.writerow(row)

    print(f"✅ CSV written to {args.out}")

if __name__ == "__main__":
    main()
