#!/usr/bin/env python3
import os
import json
import argparse
import joblib
import pandas as pd

# 🔁 adapte si ton fichier a un autre nom
from extract_features import extract_msi_features, count_pe_structure, FEATURES

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(PROJECT_ROOT, "ml", "models")

DEFAULT_MODEL_PATH = os.path.join(MODELS_DIR, "custom_randomforest.joblib")
DEFAULT_FEATS_PATH = os.path.join(MODELS_DIR, "custom_features.txt")

def load_feature_list(path: str):
    """
    On charge la liste exacte des features utilisée au train (ordre important).
    Fallback: FEATURES (dans ton extract) si le fichier n'existe pas.
    """
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            feats = [line.strip() for line in f if line.strip()]
        if feats:
            return feats
    return list(FEATURES)

def find_extracted_folder(bin_root: str, msi_id: str):
    """
    En training, tu utilises: Binary/<benign|malicious>/<msi_id>/
    En prod/predict, on ne connait pas le label.
    Donc on cherche:
      - Binary/benign/<msi_id>/
      - Binary/malicious/<msi_id>/
    Sinon: None
    """
    for sub in ["benign", "malicious"]:
        p = os.path.join(bin_root, sub, msi_id)
        if os.path.isdir(p):
            return p
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--msi", required=True, help="Path to MSI file")
    ap.add_argument("--bin", default=os.path.join(PROJECT_ROOT, "Binary"),
                    help="Binary extraction root (Binary/benign/<msi_id>/...)")
    ap.add_argument("--model", default=DEFAULT_MODEL_PATH, help="Path to .joblib model")
    ap.add_argument("--features", default=DEFAULT_FEATS_PATH, help="Path to features.txt (saved at train)")
    ap.add_argument("--threshold", type=float, default=0.5, help="Decision threshold for malware")
    ap.add_argument("--json", action="store_true", help="Output JSON only (quiet mode)")
    args = ap.parse_args()

    if not os.path.exists(args.msi):
        raise FileNotFoundError(f"MSI not found: {args.msi}")
    if not os.path.exists(args.model):
        raise FileNotFoundError(f"Model not found: {args.model}")

    msi_name = os.path.basename(args.msi)
    msi_id = os.path.splitext(msi_name)[0]
    bin_root = os.path.abspath(args.bin)

    # 1) Load model + feature list (ordre exact)
    model = joblib.load(args.model)
    feat_list = load_feature_list(args.features)

    # 2) Extract MSI-level features
    feats = extract_msi_features(args.msi)

    # 3) Extract PE-structure features (si dossier extrait dispo)
    extracted_root = find_extracted_folder(bin_root, msi_id)
    if extracted_root:
        feats.update(count_pe_structure(extracted_root))
    else:
        feats.update({"nb_pe_files": 0.0, "nb_exe": 0.0, "nb_dll": 0.0})

    # 4) Build X with correct columns/order
    row = {k: float(feats.get(k, 0.0)) for k in feat_list}
    X = pd.DataFrame([row], columns=feat_list)

    # 5) Predict
    if hasattr(model, "predict_proba"):
        proba_mal = float(model.predict_proba(X)[0][1])  # class 1 = malicious
    else:
        # fallback (rare): pas de predict_proba
        proba_mal = float(model.predict(X)[0])

    pred = 1 if proba_mal >= args.threshold else 0

    out = {
        "msi_id": msi_id,
        "file": msi_name,
        "threshold": args.threshold,
        "proba_malicious": round(proba_mal, 6),
        "prediction": int(pred),
        "prediction_label": "malicious" if pred == 1 else "benign",
        "used_extracted_folder": extracted_root,
        "nb_features": len(feat_list),
    }

    if args.json:
        print(json.dumps(out, ensure_ascii=False))
        return

    print("=== PREDICTION ===")
    print(json.dumps(out, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
