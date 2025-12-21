#!/usr/bin/env python3
import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

# =====================
# CONFIG (MSI_ANALYSIS/)
# =====================
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET = os.path.join(PROJECT_ROOT, "ml", "dataset_safari13_msi.csv")

LABEL = "label"

# Safari MSI-level features (agrégées par MSI)
FEATURES = [
    "nb_pe",

    "SectionsMaxEntropy_mean", "SectionsMaxEntropy_min", "SectionsMaxEntropy_max",
    "ResourcesMaxEntropy_mean", "ResourcesMaxEntropy_min", "ResourcesMaxEntropy_max",
    "ResourcesMinEntropy_mean", "ResourcesMinEntropy_min", "ResourcesMinEntropy_max",
    "SectionsMinEntropy_mean", "SectionsMinEntropy_min", "SectionsMinEntropy_max",

    "VersionInformationSize_max",

    "DllCharacteristics_mode",
    "Characteristics_mode",
    "Machine_mode",
    "Subsystem_mode",
    "ImageBase_mode",
    "SizeOfOptionalHeader_mode",
    "MajorSubsystemVersion_mode",
    "MajorOperatingSystemVersion_mode",
]

def main():
    if not os.path.exists(DATASET):
        raise FileNotFoundError(
            f"Dataset introuvable: {DATASET}\n"
            "Lance d'abord: ml/extract_safari13_msi.py"
        )

    df = pd.read_csv(DATASET)

    # On enlève l'identifiant si présent (pas une feature)
    if "msi_id" in df.columns:
        df = df.drop(columns=["msi_id"])

    # Vérif colonnes
    missing = [c for c in FEATURES + [LABEL] if c not in df.columns]
    if missing:
        raise ValueError(f"Colonnes manquantes dans le CSV: {missing}")

    X = df[FEATURES]
    y = df[LABEL]

    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(Xtr, ytr)
    pred = model.predict(Xte)

    print("=== Safari (MSI-level) — Random Forest ===")
    print("Rows:", df.shape[0], "| Features:", X.shape[1])
    print("Accuracy:", accuracy_score(yte, pred))
    print("CM:\n", confusion_matrix(yte, pred))
    print(classification_report(yte, pred))

if __name__ == "__main__":
    main()
