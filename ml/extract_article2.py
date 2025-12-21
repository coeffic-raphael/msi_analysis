#!/usr/bin/env python3
import os
import pandas as pd
import pefile
from collections import defaultdict

# =====================
# CONFIG (MSI_ANALYSIS/)
# =====================
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN_DIR = os.path.join(PROJECT_ROOT, "Binary")
BENIGN_DIR = os.path.join(BIN_DIR, "benign")
MALICIOUS_DIR = os.path.join(BIN_DIR, "malicious")

OUT_CSV = os.path.join(PROJECT_ROOT, "ml", "dataset_yugai_msi.csv")
PE_EXTS = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr"}

# =====================
# Yugai features
# =====================
RT_ICON = pefile.RESOURCE_TYPE.get("RT_ICON", 3)
RT_VERSION = pefile.RESOURCE_TYPE.get("RT_VERSION", 16)
RT_MANIFEST = pefile.RESOURCE_TYPE.get("RT_MANIFEST", 24)


def has_resource_type(pe: pefile.PE, rtype_id: int) -> int:
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return 0
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if getattr(entry, "id", None) == rtype_id:
            return 1
    return 0


def get_version_info_strings(pe: pefile.PE) -> dict:
    keys = [
        "CompanyName",
        "FileVersion",
        "ProductName",
        "FileDescription",
        "LegalCopyright",
        "ProductVersion",
    ]
    present = {k: 0 for k in keys}
    try:
        if hasattr(pe, "FileInfo") and pe.FileInfo:
            for fi in pe.FileInfo:
                if hasattr(fi, "StringTable"):
                    for st in fi.StringTable:
                        for k, v in st.entries.items():
                            kk = (
                                k.decode(errors="ignore")
                                if isinstance(k, (bytes, bytearray))
                                else str(k)
                            )
                            if kk in present:
                                vv = (
                                    v.decode(errors="ignore")
                                    if isinstance(v, (bytes, bytearray))
                                    else str(v)
                                )
                                if vv.strip():
                                    present[kk] = 1
    except Exception:
        pass
    return present


def extract_yugai_features(pe_path: str) -> dict:
    pe = pefile.PE(pe_path, fast_load=False)
    vi = get_version_info_strings(pe)
    return {
        "RT_ICON": has_resource_type(pe, RT_ICON),
        "RT_MANIFEST": has_resource_type(pe, RT_MANIFEST),
        "RT_VERSION": has_resource_type(pe, RT_VERSION),
        "CheckSum_nonzero": 1 if getattr(pe.OPTIONAL_HEADER, "CheckSum", 0) != 0 else 0,
        "DllCharacteristics_nonzero": 1
        if getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0) != 0
        else 0,
        "NumberOfSections": int(getattr(pe.FILE_HEADER, "NumberOfSections", 0)),
        "CompanyName_present": vi["CompanyName"],
        "FileVersion_present": vi["FileVersion"],
        "ProductName_present": vi["ProductName"],
        "FileDescription_present": vi["FileDescription"],
        "LegalCopyright_present": vi["LegalCopyright"],
        "ProductVersion_present": vi["ProductVersion"],
    }


def iter_pe_files(root_dir: str):
    for dirpath, _, filenames in os.walk(root_dir):
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in PE_EXTS:
                yield os.path.join(dirpath, fn)


# =====================
# FIX #1: include MSI with zero PE
# We enumerate MSI folders directly, then scan PE inside each folder.
# =====================
def list_msi_folders(class_dir: str):
    """
    class_dir = Binary/benign or Binary/malicious
    expects structure:
      Binary/<class>/<msi_id>/... (files)
    returns list of absolute folder paths for each msi_id.
    """
    if not os.path.isdir(class_dir):
        return []
    out = []
    for name in sorted(os.listdir(class_dir)):
        p = os.path.join(class_dir, name)
        if os.path.isdir(p):
            out.append(p)
    return out


def get_msi_id_from_folder(msi_folder: str) -> str:
    return os.path.basename(msi_folder)


# =====================
# FIX #2: align columns with train
# We output a single "NumberOfSections" feature (MSI-level),
# using max() (you can switch to mean if you prefer).
# =====================
def agg_msi(msi_id: str, label: int, rows: list) -> dict:
    out = {"msi_id": msi_id, "label": label, "nb_pe": len(rows)}

    bin_fields = [
        "RT_ICON",
        "RT_MANIFEST",
        "RT_VERSION",
        "CheckSum_nonzero",
        "DllCharacteristics_nonzero",
        "CompanyName_present",
        "FileVersion_present",
        "ProductName_present",
        "FileDescription_present",
        "LegalCopyright_present",
        "ProductVersion_present",
    ]
    for f in bin_fields:
        out[f] = int(max(r.get(f, 0) for r in rows)) if rows else 0

    secs = [r.get("NumberOfSections", 0) for r in rows]
    out["NumberOfSections"] = int(max(secs)) if secs else 0

    return out


def process_class(class_dir: str, label: int, tag: str, groups: dict):
    msi_folders = list_msi_folders(class_dir)
    print(f"\n{tag} total MSI folders: {len(msi_folders)}")

    for i, msi_folder in enumerate(msi_folders, start=1):
        msi_id = get_msi_id_from_folder(msi_folder)

        pe_list = list(iter_pe_files(msi_folder))
        print(f"{tag} MSI [{i}/{len(msi_folders)}] {msi_id} ({len(pe_list)} PE)")

        rows = []
        for j, pe_path in enumerate(pe_list, start=1):
            print(f"   ↳ PE [{j}/{len(pe_list)}] {os.path.basename(pe_path)}")
            try:
                rows.append(extract_yugai_features(pe_path))
            except Exception as e:
                print(f"   [WARN] Skip {pe_path} ({e})")

        groups.append(agg_msi(msi_id, label, rows))


def main():
    if not os.path.isdir(BENIGN_DIR) or not os.path.isdir(MALICIOUS_DIR):
        raise FileNotFoundError(f"Missing {BENIGN_DIR} or {MALICIOUS_DIR}")

    out_rows = []
    process_class(BENIGN_DIR, 0, "🟢 BENIGN", out_rows)
    process_class(MALICIOUS_DIR, 1, "🔴 MALICIOUS", out_rows)

    df = pd.DataFrame(out_rows).sort_values(["label", "msi_id"])
    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    df.to_csv(OUT_CSV, index=False)

    print("\n==============================")
    print("✅ YUGAI extraction (MSI-level) DONE")
    print("MSI rows:", df.shape[0])
    print("CSV:", OUT_CSV)
    print("Columns:", list(df.columns))
    print("==============================")


if __name__ == "__main__":
    main()

