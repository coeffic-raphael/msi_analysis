#!/usr/bin/env python3
import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET = os.path.join(PROJECT_ROOT, "ml", "dataset_yugai_msi.csv")

LABEL = "label"

FEATURES = [
    "nb_pe",

    "RT_ICON", "RT_MANIFEST", "RT_VERSION",
    "CheckSum_nonzero", "DllCharacteristics_nonzero",

    "CompanyName_present", "FileVersion_present", "ProductName_present",
    "FileDescription_present", "LegalCopyright_present", "ProductVersion_present",

    "NumberOfSections",
]

def eval_model(name, model, X_train, X_test, y_train, y_test):
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    print(f"\n=== {name} ===")
    print("Accuracy:", accuracy_score(y_test, pred))
    print("Confusion Matrix:\n", confusion_matrix(y_test, pred))
    print(classification_report(y_test, pred, digits=4))

def main():
    if not os.path.exists(DATASET):
        raise FileNotFoundError(f"Dataset introuvable: {DATASET}")

    df = pd.read_csv(DATASET)

    # msi_id n’est pas une feature ML
    if "msi_id" in df.columns:
        df = df.drop(columns=["msi_id"])

    X = df[FEATURES]
    y = df[LABEL]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    print("=== Yugai (MSI-level) ===")
    print("Rows:", df.shape[0], "| Features:", X.shape[1])

    eval_model("Yugai — Naive Bayes", GaussianNB(), X_train, X_test, y_train, y_test)
    eval_model(
        "Yugai — Random Forest",
        RandomForestClassifier(n_estimators=100, random_state=42),
        X_train, X_test, y_train, y_test
    )
    eval_model(
        "Yugai — C4.5-like (DecisionTree entropy)",
        DecisionTreeClassifier(criterion="entropy", random_state=42),
        X_train, X_test, y_train, y_test
    )

if __name__ == "__main__":
    main()


