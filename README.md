# MSI Malware Detection

> Static machine-learning detection of malicious Microsoft Installer (`.msi`) packages using MSI table features and embedded PE payload structure.

📄 **Research report**: [MSI_detection.pdf](./MSI_detection.pdf)

Dataset curation and ML implementation by **Raphael Coeffic**.  
Research project developed with collaboration from **Guy Levy**.

---

## Results at a Glance

| Approach | Model | Accuracy | Precision (malicious) | Recall (malicious) | F1 (malicious) |
|---|---|---:|---:|---:|---:|
| Tyagi-inspired PE structure | Random Forest | 0.76 | 0.74 | 0.80 | 0.77 |
| Yugai-inspired PE metadata | Random Forest | 0.76 | 0.71 | 0.88 | 0.79 |
| MSI-only baseline | Random Forest | 0.92 | 0.89 | 0.96 | 0.92 |
| **Proposed MSI + PE structure** | **Random Forest** | **0.94** | **0.92** | **0.96** | **0.94** |
| Proposed MSI + PE structure | Gradient Boosted DT | 0.94 | 0.89 | 1.00 | 0.94 |

Evaluation uses a fixed 75/25 train-test split on the same 200 MSI samples for each feature family: 100 benign and 100 malicious installers.

The MSI dataset used in this project was fully assembled and organized by **Raphael Coeffic** from benign installer sources and malicious sample repositories.

---

## Project Goal

Microsoft Installer files are commonly trusted by users and enterprise deployment tools, which makes them attractive containers for malware delivery. This project explores whether malicious MSI packages can be detected using static analysis only, without executing the installer.

The final model combines two complementary signals:

- **MSI-level behavior**: installer tables, custom actions, binary table presence, execution sequence statistics, suspicious keywords, size, and entropy.
- **Embedded PE structure**: counts of PE files, executables, and DLLs extracted from the MSI payload.

The main finding is that MSI-native features are already strong, but adding lightweight PE-structure information improves holdout accuracy from `0.92` to `0.94` while preserving high malicious recall.

---

## Why MSI Files Matter

MSI files are structured installer databases. Attackers can abuse that structure to hide payloads, run custom actions, trigger scripts, or install malicious binaries while appearing to distribute a legitimate application.

The project focuses on static features because they are faster, safer, and easier to integrate into a pre-execution scanning pipeline than dynamic sandbox analysis.

---

## Method Summary

```text
MSI file
  ├── MSI static analysis
  │     ├── file size and header entropy
  │     ├── Binary table presence
  │     ├── InstallExecuteSequence action counts
  │     ├── CustomAction counts and flags
  │     └── suspicious keyword hits
  │
  ├── extracted payload analysis
  │     ├── number of PE files
  │     ├── number of EXE/SCR/CPL payloads
  │     └── number of DLL/OCX payloads
  │
  └── Random Forest classifier
        └── benign vs malicious
```

The research also compares the custom feature set against two literature-inspired baselines:

- **Tyagi-inspired features**: PE header and entropy features aggregated at MSI level.
- **Yugai-inspired features**: resource, version-info, checksum, and section-count metadata from embedded PE files.

---

## Feature Sets

### Custom MSI Features

Implemented in [`ml/extract_features.py`](./ml/extract_features.py):

- `log_size`
- `head_entropy`
- `has_binary`
- `ies_action_count`
- `ies_executable_action_count`
- `ca_count`
- `ca_exe_count`
- `ca_dll_count`
- `ca_deferred_count`
- `ca_commit_count`
- `ca_suspicious_kw_hits`
- `lc_count`
- `nb_pe_files`
- `nb_exe`
- `nb_dll`

The exact feature order used by the saved model is stored in [`ml/models/custom_features.txt`](./ml/models/custom_features.txt).

### Article-Inspired Features

- [`ml/extract_article1.py`](./ml/extract_article1.py): Tyagi-style PE header and entropy features.
- [`ml/extract_article2.py`](./ml/extract_article2.py): Yugai-style PE resource and metadata features.

---

## Model Selection

Several classifiers were evaluated on the proposed MSI + PE feature set.

| Model | Accuracy | Precision (malicious) | Recall (malicious) | F1 (malicious) |
|---|---:|---:|---:|---:|
| Random Forest | 0.94 | 0.92 | 0.96 | 0.94 |
| Gradient Boosted Decision Trees | 0.94 | 0.89 | 1.00 | 0.94 |
| Extra Trees | 0.90 | 0.88 | 0.92 | 0.90 |
| k-Nearest Neighbors | 0.76 | 0.69 | 0.96 | 0.80 |
| Logistic Regression | 0.72 | 0.67 | 0.88 | 0.76 |
| Support Vector Machine | 0.54 | 0.52 | 1.00 | 0.68 |

Random Forest was selected as the final model because it matched the best accuracy while producing fewer false positives than Gradient Boosted Decision Trees.

---

## Repository Structure

```text
.
├── MSI_detection.pdf              # Full research report
├── ml/
│   ├── extract_features.py         # Custom MSI + PE feature extraction
│   ├── extract_article1.py         # Tyagi-inspired feature extraction
│   ├── extract_article2.py         # Yugai-inspired feature extraction
│   ├── train.py                    # Fair comparison on shared MSI IDs
│   ├── train_article1.py           # Standalone Tyagi-style training
│   ├── train_article2.py           # Standalone Yugai-style training
│   ├── predict.py                  # Inference script for one MSI file
│   └── models/
│       ├── custom_randomforest.joblib
│       └── custom_features.txt
```

The dataset and extracted MSI payloads are not included in this repository.

---

## Usage

### 1. Install dependencies

This project expects Python 3 and the following core packages:

```bash
pip install pandas numpy scikit-learn joblib pefile
```

The custom MSI feature extractor also expects `msiinfo` from `msitools` to be available on the system path.

### 2. Expected data layout

```text
dataset/
├── benign/
│   └── sample.msi
└── malicious/
    └── sample.msi

Binary/
├── benign/
│   └── sample/
│       └── extracted_payload.exe
└── malicious/
    └── sample/
        └── extracted_payload.exe
```

`dataset/` contains the original MSI files. `Binary/` contains extracted payload folders named after each MSI ID.

### 3. Extract custom features

```bash
python ml/extract_features.py \
  --dataset dataset \
  --bin Binary \
  --out ml/features.csv
```

### 4. Train and compare models

```bash
python ml/train.py
```

`ml/train.py` loads the custom, Tyagi-inspired, and Yugai-inspired feature CSVs, intersects them by `msi_id`, applies one shared 75/25 split, and evaluates all approaches on the same samples.

### 5. Predict a single MSI

```bash
python ml/predict.py \
  --msi path/to/file.msi \
  --bin Binary \
  --model ml/models/custom_randomforest.joblib \
  --features ml/models/custom_features.txt \
  --threshold 0.5
```

JSON output is available with:

```bash
python ml/predict.py --msi path/to/file.msi --json
```

---

## Limitations

- The reported experiment uses a small balanced dataset of 200 MSI files.
- The evaluation is a fixed holdout split, not an external real-world test set.
- Results may not generalize to packed, heavily obfuscated, or newly emerging MSI malware families.
- Static analysis cannot observe runtime behavior such as network activity, registry modification, or delayed payload execution.
- The dataset and extraction artifacts are not included, so full reproduction requires rebuilding the MSI corpus.

---

## Key Takeaways

- MSI-level installer logic is a strong malware detection signal by itself.
- Embedded PE composition adds useful complementary information.
- Random Forest provides a strong accuracy/interpretability trade-off on this small static feature dataset.
- A lightweight static model can act as a pre-execution triage layer before deeper sandbox analysis.
