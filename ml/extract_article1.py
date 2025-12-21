#!/usr/bin/env python3
import os
import math
import pandas as pd
import pefile
from collections import Counter, defaultdict

# =====================
# CONFIG (MSI_ANALYSIS/)
# =====================
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../MSI_ANALYSIS

BIN_DIR = os.path.join(PROJECT_ROOT, "Binary")
BENIGN_DIR = os.path.join(BIN_DIR, "benign")
MALICIOUS_DIR = os.path.join(BIN_DIR, "malicious")

OUT_CSV = os.path.join(PROJECT_ROOT, "ml", "dataset_safari13_msi.csv")

PE_EXTS = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr"}

# =====================
# HELPERS
# =====================
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    n = len(data)
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent

def section_entropies(pe: pefile.PE):
    ents = []
    for s in pe.sections:
        try:
            data = s.get_data()
        except Exception:
            data = b""
        ents.append(shannon_entropy(data))
    if not ents:
        return 0.0, 0.0
    return min(ents), max(ents)

def resource_entropies(pe: pefile.PE):
    ents = []
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return 0.0, 0.0
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if not hasattr(entry, "directory"):
            continue
        for e2 in entry.directory.entries:
            if not hasattr(e2, "directory"):
                continue
            for e3 in e2.directory.entries:
                if not hasattr(e3, "data"):
                    continue
                try:
                    rva = e3.data.struct.OffsetToData
                    size = e3.data.struct.Size
                    data = pe.get_data(rva, size)
                except Exception:
                    data = b""
                ents.append(shannon_entropy(data))
    if not ents:
        return 0.0, 0.0
    return min(ents), max(ents)

def version_info_size(pe: pefile.PE) -> int:
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return 0
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id == pefile.RESOURCE_TYPE.get("RT_VERSION", 16):
            total = 0
            for e2 in getattr(entry, "directory", []).entries:
                for e3 in getattr(e2, "directory", []).entries:
                    try:
                        total += e3.data.struct.Size
                    except Exception:
                        pass
            return total
    return 0

def extract_one(path: str) -> dict:
    pe = pefile.PE(path, fast_load=False)

    sec_min, sec_max = section_entropies(pe)
    res_min, res_max = resource_entropies(pe)
    ver_sz = int(version_info_size(pe))

    return {
        "DllCharacteristics": int(pe.OPTIONAL_HEADER.DllCharacteristics),
        "Characteristics": int(pe.FILE_HEADER.Characteristics),
        "Machine": int(pe.FILE_HEADER.Machine),
        "VersionInformationSize": ver_sz,
        "Subsystem": int(pe.OPTIONAL_HEADER.Subsystem),
        "ImageBase": int(pe.OPTIONAL_HEADER.ImageBase),
        "SizeOfOptionalHeader": int(pe.FILE_HEADER.SizeOfOptionalHeader),
        "MajorSubsystemVersion": int(pe.OPTIONAL_HEADER.MajorSubsystemVersion),
        "SectionsMaxEntropy": float(sec_max),
        "ResourcesMaxEntropy": float(res_max),
        "ResourcesMinEntropy": float(res_min),
        "MajorOperatingSystemVersion": int(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion),
        "SectionsMinEntropy": float(sec_min),
    }

def iter_pe_files(root_dir: str):
    for dirpath, _, filenames in os.walk(root_dir):
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in PE_EXTS:
                yield os.path.join(dirpath, fn)

def get_msi_id_from_pe_path(pe_path: str) -> str:
    rel = os.path.relpath(pe_path, BIN_DIR)
    parts = rel.split(os.sep)
    # Binary/<class>/<msi_id>/...
    if len(parts) >= 3:
        return parts[1]
    return "UNKNOWN"

def mode_or_zero(values):
    values = [v for v in values if v is not None]
    if not values:
        return 0
    return Counter(values).most_common(1)[0][0]

def agg_group(msi_id: str, label: int, rows: list) -> dict:
    out = {"msi_id": msi_id, "label": label, "nb_pe": len(rows)}

    num_fields = [
        "SectionsMaxEntropy", "ResourcesMaxEntropy", "ResourcesMinEntropy", "SectionsMinEntropy"
    ]
    for f in num_fields:
        vals = [r[f] for r in rows if f in r]
        out[f"{f}_mean"] = float(pd.Series(vals).mean()) if vals else 0.0
        out[f"{f}_min"]  = float(pd.Series(vals).min())  if vals else 0.0
        out[f"{f}_max"]  = float(pd.Series(vals).max())  if vals else 0.0

    vis = [r["VersionInformationSize"] for r in rows if "VersionInformationSize" in r]
    out["VersionInformationSize_max"] = int(max(vis)) if vis else 0

    mode_fields = [
        "DllCharacteristics", "Characteristics", "Machine", "Subsystem",
        "ImageBase", "SizeOfOptionalHeader", "MajorSubsystemVersion",
        "MajorOperatingSystemVersion"
    ]
    for f in mode_fields:
        vals = [r.get(f) for r in rows]
        out[f"{f}_mode"] = int(mode_or_zero(vals))

    return out

def build_msi_map(root_dir: str) -> dict:
    msi_to_pe = defaultdict(list)
    for pe_path in iter_pe_files(root_dir):
        msi_to_pe[get_msi_id_from_pe_path(pe_path)].append(pe_path)
    return msi_to_pe

def process_class(root_dir: str, label: int, tag: str, groups: dict, labels: dict):
    msi_to_pe = build_msi_map(root_dir)
    msi_ids = sorted(msi_to_pe.keys())
    print(f"\n{tag} total MSI: {len(msi_ids)}")

    for i, msi_id in enumerate(msi_ids, start=1):
        pe_list = msi_to_pe[msi_id]
        labels[msi_id] = label
        print(f"{tag} MSI [{i}/{len(msi_ids)}] {msi_id} ({len(pe_list)} PE)")

        for j, pe_path in enumerate(pe_list, start=1):
            # mini progress interne (tu peux commenter si trop verbeux)
            print(f"   ↳ PE [{j}/{len(pe_list)}] {os.path.basename(pe_path)}")
            try:
                groups[msi_id].append(extract_one(pe_path))
            except Exception as e:
                print(f"   [WARN] Skip {pe_path} ({e})")

def main():
    if not os.path.isdir(BENIGN_DIR) or not os.path.isdir(MALICIOUS_DIR):
        raise FileNotFoundError(
            "Je ne trouve pas Binary/benign ou Binary/malicious.\n"
            f"Attendu: {BENIGN_DIR} et {MALICIOUS_DIR}"
        )

    groups = defaultdict(list)
    labels = {}

    process_class(BENIGN_DIR, 0, "🟢 BENIGN", groups, labels)
    process_class(MALICIOUS_DIR, 1, "🔴 MALICIOUS", groups, labels)

    out_rows = []
    for msi_id, rows in groups.items():
        out_rows.append(agg_group(msi_id, labels.get(msi_id, -1), rows))

    df = pd.DataFrame(out_rows).sort_values(["label", "msi_id"])
    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    df.to_csv(OUT_CSV, index=False)

    print("\n==============================")
    print("✅ SAFARI extraction (MSI-level) DONE")
    print("MSI rows:", df.shape[0])
    print("CSV:", OUT_CSV)
    print("Columns:", list(df.columns))
    print("==============================")

if __name__ == "__main__":
    main()
