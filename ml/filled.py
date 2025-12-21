#!/usr/bin/env python3
import os
import pandas as pd

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# CSV canonique: celui qui a tous les MSI (souvent ton custom features.csv)
CANONICAL = os.path.join(PROJECT_ROOT, "ml", "features.csv")

SAFARI_IN  = os.path.join(PROJECT_ROOT, "ml", "dataset_safari13_msi.csv")
YUGAI_IN   = os.path.join(PROJECT_ROOT, "ml", "dataset_yugai_msi.csv")

SAFARI_OUT = os.path.join(PROJECT_ROOT, "ml", "dataset_safari13_msi_filled.csv")
YUGAI_OUT  = os.path.join(PROJECT_ROOT, "ml", "dataset_yugai_msi_filled.csv")

LABEL_COL = "label"

def normalize_msi_id(x: str) -> str:
    # accepte "0.0.7.msi" ou "0.0.7"
    x = str(x)
    if x.lower().endswith(".msi"):
        x = x[:-4]
    return x

def load_ids_from_canonical(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)

    # si ton fichier custom a "file" (nom msi), on l'utilise comme ID
    if "msi_id" in df.columns:
        df["msi_id"] = df["msi_id"].map(normalize_msi_id)
        base = df[["msi_id", LABEL_COL]].copy()
        return base

    if "file" in df.columns:
        base = df[["file", LABEL_COL]].copy()
        base["msi_id"] = base["file"].map(normalize_msi_id)
        base = base.drop(columns=["file"])
        return base

    raise ValueError("CANONICAL doit contenir soit 'msi_id' soit 'file' + 'label'.")

def fill_missing_rows(canon: pd.DataFrame, df: pd.DataFrame, name: str) -> pd.DataFrame:
    if "msi_id" not in df.columns:
        # si pas de msi_id mais un msi_id implicite
        if "file" in df.columns:
            df = df.copy()
            df["msi_id"] = df["file"].map(normalize_msi_id)
        else:
            raise ValueError(f"{name}: pas de colonne 'msi_id' ni 'file'.")

    df = df.copy()
    df["msi_id"] = df["msi_id"].map(normalize_msi_id)

    # on garde label depuis canonical (source de vérité)
    # et on merge pour récupérer toutes les lignes
    merged = canon.merge(df, on="msi_id", how="left", suffixes=("", "_old"))

    # si label existe aussi dans df, on préfère canonical
    if f"{LABEL_COL}_old" in merged.columns:
        merged = merged.drop(columns=[f"{LABEL_COL}_old"])

    # colonnes features = toutes sauf msi_id et label
    feature_cols = [c for c in merged.columns if c not in ("msi_id", LABEL_COL)]

    # Remplir NaN par 0 pour features manquantes
    merged[feature_cols] = merged[feature_cols].fillna(0)

    # (optionnel) convertir en int certaines colonnes binaires si tu veux
    # mais pas obligatoire pour RF
    return merged

def main():
    for p in [CANONICAL, SAFARI_IN, YUGAI_IN]:
        if not os.path.exists(p):
            raise FileNotFoundError(f"Fichier introuvable: {p}")

    canon = load_ids_from_canonical(CANONICAL)
    print("Canonical MSI:", canon.shape[0])

    safari = pd.read_csv(SAFARI_IN)
    yugai  = pd.read_csv(YUGAI_IN)

    safari_filled = fill_missing_rows(canon, safari, "Safari")
    yugai_filled  = fill_missing_rows(canon, yugai, "Yugai")

    safari_filled.to_csv(SAFARI_OUT, index=False)
    yugai_filled.to_csv(YUGAI_OUT, index=False)

    print("✅ Safari filled:", safari_filled.shape, "->", SAFARI_OUT)
    print("✅ Yugai filled :", yugai_filled.shape,  "->", YUGAI_OUT)

if __name__ == "__main__":
    main()
