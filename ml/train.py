

# #!/usr/bin/env python3
# import os
# import numpy as np
# import pandas as pd

# from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.metrics import confusion_matrix, classification_report

# PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# DATASET = os.path.join(PROJECT_ROOT, "ml", "features.csv")

# LABEL_COL = "label"

# EXPECTED_FEATURES = [
#     # MSI features
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
#     # PE structure
#     "nb_pe_files",
#     "nb_exe",
#     "nb_dll",
# ]

# def main():
#     if not os.path.exists(DATASET):
#         raise FileNotFoundError(f"Dataset introuvable: {DATASET}")

#     df = pd.read_csv(DATASET)

#     if LABEL_COL not in df.columns:
#         raise ValueError(f"Colonne label '{LABEL_COL}' absente. Colonnes: {list(df.columns)}")

#     features = [f for f in EXPECTED_FEATURES if f in df.columns]
#     missing = [f for f in EXPECTED_FEATURES if f not in df.columns]
#     if missing:
#         print("⚠️ Features manquantes (ignorées):", missing)

#     if not features:
#         raise ValueError("Aucune feature trouvée dans le CSV.")

#     X = df[features].copy()
#     y = df[LABEL_COL].copy()

#     print("=== DATASET INFO ===")
#     print("Rows:", df.shape[0])
#     print("Features used:", len(features))
#     print("Label distribution:\n", y.value_counts().sort_index())
#     print()

#     # 1) Holdout test set (final evaluation)
#     X_train, X_test, y_train, y_test = train_test_split(
#         X, y, test_size=0.25, random_state=42, stratify=y
#     )

#     model = RandomForestClassifier(
#         n_estimators=300,
#         random_state=42,
#         class_weight="balanced",
#         n_jobs=-1
#     )

#     # 2) Cross-validation on TRAIN only (to report stable performance)
#     skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
#     scoring = {
#         "accuracy": "accuracy",
#         "f1": "f1",
#         "precision": "precision",
#         "recall": "recall",
#     }

#     cv = cross_validate(model, X_train, y_train, cv=skf, scoring=scoring, n_jobs=-1)

#     print("=== 5-FOLD CV (on TRAIN split only) ===")
#     for k in scoring.keys():
#         vals = cv[f"test_{k}"]
#         print(f"{k:9s}: {vals.mean():.4f} ± {vals.std():.4f}")
#     print()

#     # 3) Fit on full train and evaluate on HOLDOUT test
#     model.fit(X_train, y_train)
#     pred = model.predict(X_test)

#     print("=== FINAL HOLDOUT TEST (25%) ===")
#     print("Confusion Matrix:\n", confusion_matrix(y_test, pred))
#     print()
#     print(classification_report(y_test, pred, digits=4))

#     # Feature importances
#     imp = pd.Series(model.feature_importances_, index=features).sort_values(ascending=False)
#     print("\n=== TOP FEATURE IMPORTANCES ===")
#     print(imp.head(15))

# if __name__ == "__main__":
#     main()

#!/usr/bin/env python3
import os
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score
import joblib

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CSV_SAFARI = os.path.join(PROJECT_ROOT, "ml", "dataset_safari13_msi_filled.csv")
CSV_YUGAI  = os.path.join(PROJECT_ROOT, "ml", "dataset_yugai_msi_filled.csv")
CSV_CUSTOM = os.path.join(PROJECT_ROOT, "ml", "features.csv")

OUT_DIR = os.path.join(PROJECT_ROOT, "ml", "models")
os.makedirs(OUT_DIR, exist_ok=True)

LABEL_COL = "label"
ID_COL = "msi_id"      # idéal
FALLBACK_FILE_COL = "file"

# -------------------------
# Features par méthode
# -------------------------
FEATURES_SAFARI = [
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

FEATURES_YUGAI = [
    "nb_pe",
    "RT_ICON", "RT_MANIFEST", "RT_VERSION",
    "CheckSum_nonzero", "DllCharacteristics_nonzero",
    "CompanyName_present", "FileVersion_present", "ProductName_present",
    "FileDescription_present", "LegalCopyright_present", "ProductVersion_present",
    "NumberOfSections",
]

FEATURES_CUSTOM = [
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
    "nb_pe_files",
    "nb_exe",
    "nb_dll",
]

# -------------------------
# Helpers
# -------------------------
def load_df(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        raise FileNotFoundError(f"CSV introuvable: {path}")
    df = pd.read_csv(path)

    if LABEL_COL not in df.columns:
        raise ValueError(f"'{LABEL_COL}' absent dans {path}. Colonnes: {list(df.columns)}")

    # Garantir un ID stable
    if ID_COL not in df.columns:
        if FALLBACK_FILE_COL in df.columns:
            df[ID_COL] = df[FALLBACK_FILE_COL].astype(str).str.replace(r"\.msi$", "", regex=True)
        else:
            raise ValueError(f"Ni '{ID_COL}' ni '{FALLBACK_FILE_COL}' dans {path}")

    df[ID_COL] = df[ID_COL].astype(str)
    return df

def check_features(df: pd.DataFrame, feats: list, name: str):
    missing = [f for f in feats if f not in df.columns]
    if missing:
        raise ValueError(f"[{name}] Features manquantes dans le CSV: {missing}")

def _cv_report(model, X_train, y_train):
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scoring = {"accuracy": "accuracy", "f1": "f1", "precision": "precision", "recall": "recall"}
    cv = cross_validate(model, X_train, y_train, cv=skf, scoring=scoring, n_jobs=-1)
    print("\n--- 5-FOLD CV (TRAIN only) ---")
    for k in scoring:
        vals = cv[f"test_{k}"]
        print(f"{k:9s}: {vals.mean():.4f} ± {vals.std():.4f}")
    return cv

def eval_one(name: str, df: pd.DataFrame, feats: list, train_ids, test_ids, do_cv=True, models=None, save_best=True):
    """
    Évalue 1 méthode (Safari/Yugai/Custom) sur le MÊME split train/test (IDs).
    - models: liste de tuples (model_name, model_obj)
    - save_best: sauvegarde uniquement le meilleur modèle (accuracy holdout) + features.txt
    """
    check_features(df, feats, name)

    dtrain = df[df[ID_COL].isin(train_ids)].copy()
    dtest  = df[df[ID_COL].isin(test_ids)].copy()

    X_train = dtrain[feats]
    y_train = dtrain[LABEL_COL]
    X_test  = dtest[feats]
    y_test  = dtest[LABEL_COL]

    print(f"\n==============================")
    print(f"=== {name} ===")
    print("Train:", X_train.shape, " Test:", X_test.shape)

    # Default: RF only (si non fourni)
    if models is None:
        models = [
            ("RandomForest", RandomForestClassifier(
                n_estimators=300, random_state=42, class_weight="balanced", n_jobs=-1
            ))
        ]

    best = None  # (acc, model_name, model_obj)

    for model_name, model in models:
        print(f"\n>>> MODEL: {model_name}")

        if do_cv:
            _cv_report(model, X_train, y_train)

        model.fit(X_train, y_train)
        pred = model.predict(X_test)

        acc = accuracy_score(y_test, pred)
        print("\n--- HOLDOUT TEST ---")
        print("Accuracy:", f"{acc:.4f}")
        print("Confusion Matrix:\n", confusion_matrix(y_test, pred))
        print(classification_report(y_test, pred, digits=4))

        if best is None or acc > best[0]:
            best = (acc, model_name, model)

    # Save best model + feature list (pratique pour Docker)
    if save_best and best is not None:
        best_acc, best_name, best_model = best
        safe_method = name.lower().replace(" ", "_")
        safe_model  = best_name.lower().replace(" ", "_")

        model_path = os.path.join(OUT_DIR, f"{safe_method}_{safe_model}.joblib")
        meta_path  = os.path.join(OUT_DIR, f"{safe_method}_features.txt")

        joblib.dump(best_model, model_path)
        with open(meta_path, "w", encoding="utf-8") as f:
            for feat in feats:
                f.write(feat + "\n")

        print(f"\n✅ BEST for {name}: {best_name} (acc={best_acc:.4f})")
        print(f"✅ saved: {model_path}")

    return best

def main():
    safari = load_df(CSV_SAFARI)
    yugai  = load_df(CSV_YUGAI)
    custom = load_df(CSV_CUSTOM)

    # ✅ INTERSECTION (comparaison "fair")
    common_ids = set(safari[ID_COL]) & set(yugai[ID_COL]) & set(custom[ID_COL])
    common_ids = sorted(common_ids)

    if len(common_ids) < 20:
        raise ValueError(f"Trop peu d'IDs communs: {len(common_ids)}. Vérifie tes msi_id.")

    # Vérif cohérence des labels sur l'intersection
    lab_c = custom.set_index(ID_COL)[LABEL_COL].to_dict()
    lab_s = safari.set_index(ID_COL)[LABEL_COL].to_dict()
    lab_y = yugai.set_index(ID_COL)[LABEL_COL].to_dict()

    for mid in common_ids:
        if not (lab_c[mid] == lab_s[mid] == lab_y[mid]):
            raise ValueError(f"Label mismatch pour {mid}: custom={lab_c[mid]} safari={lab_s[mid]} yugai={lab_y[mid]}")

    y_all = np.array([lab_c[mid] for mid in common_ids])

    # ✅ SPLIT UNIQUE basé sur les msi_id
    train_ids, test_ids = train_test_split(
        common_ids,
        test_size=0.25,
        random_state=42,
        stratify=y_all
    )

    # Sauver les splits pour preuve / reproductibilité
    with open(os.path.join(OUT_DIR, "train_ids.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(train_ids))
    with open(os.path.join(OUT_DIR, "test_ids.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(test_ids))

    print("=== COMMON SPLIT ===")
    print("Common MSI:", len(common_ids))
    print("Train IDs:", len(train_ids), " Test IDs:", len(test_ids))
    print("Coverage:", "custom=", custom.shape[0], " safari=", safari.shape[0], " yugai=", yugai.shape[0])
    print("✅ saved split lists in ml/models/")

    # Safari: RF only
    eval_one(
        "Safari13",
        safari,
        FEATURES_SAFARI,
        train_ids,
        test_ids,
        do_cv=True,
        models=[
            ("RandomForest", RandomForestClassifier(
                n_estimators=300, random_state=42, class_weight="balanced", n_jobs=-1
            ))
        ],
        save_best=True
    )

    # Yugai: plusieurs modèles (comme ton ancien script)
    eval_one(
        "Yugai",
        yugai,
        FEATURES_YUGAI,
        train_ids,
        test_ids,
        do_cv=True,
        models=[
            ("NaiveBayes_Gaussian", GaussianNB()),
            ("DecisionTree_entropy", DecisionTreeClassifier(criterion="entropy", random_state=42)),
            ("RandomForest", RandomForestClassifier(
                n_estimators=300, random_state=42, class_weight="balanced", n_jobs=-1
            )),
        ],
        save_best=True
    )

    # Custom: RF only (tu peux ajouter d'autres plus tard)
    eval_one(
        "Custom",
        custom,
        FEATURES_CUSTOM,
        train_ids,
        test_ids,
        do_cv=True,
        models=[
            ("RandomForest", RandomForestClassifier(
                n_estimators=300, random_state=42, class_weight="balanced", n_jobs=-1
            ))
        ],
        save_best=True
    )

if __name__ == "__main__":
    main()
